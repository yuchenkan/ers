#include <stdarg.h>

#include <live-thread.h>
#include <live-thread-local.h>

#include <public/common.h>

#include <rtld.h>
#include <common.h>
#include <helper.h>
#include <live-signal-thread.h>
#include <live-thread-recorder.h>

#include <lib/util.h>
#include <lib/rbtree.h>
#include <lib/malloc.h>
#include <lib/syscall.h>
#include <lib/atomic.h>

#define THREAD_SIG_STACK_SIZE	(2 * 4096)

struct thread_group;

struct eri_live_thread
{
  struct thread_group *group;
  struct eri_live_signal_thread *sig_th;
  uint64_t id;
  int32_t alive;
  int32_t *clear_tid;

  struct eri_live_thread_recorder *rec;

  struct thread_context *ctx;

  int32_t tid;

  struct eri_stack sig_alt_stack;

  uint8_t sig_stack[2 * THREAD_SIG_STACK_SIZE];

  eri_aligned16 uint8_t stack[0];
};

struct sig_fd_mask
{
  uint64_t ref_count;
  int32_t lock;
  struct eri_sigset mask;
};

struct sig_fd
{
  int32_t fd;
  struct sig_fd_mask *mask;
  int32_t flags;

  ERI_RBT_NODE_FIELDS (sig_fd, struct sig_fd)
};

struct thread_group
{
  struct eri_mtpool *pool;

  uint64_t map_start;
  uint64_t map_end;

  uint64_t buf_start;
  uint64_t buf_end;

  uint64_t ref_count;
  int32_t pid;

  int32_t sig_fd_lock;
  ERI_RBT_TREE_FIELDS (sig_fd, struct sig_fd)

  uint64_t *atomic_table;
  uint64_t atomic_table_size;

  uint64_t th_id;
  uint64_t stack_size;
};

ERI_DEFINE_RBTREE (static, sig_fd, struct thread_group, struct sig_fd,
		   int32_t, eri_less_than)

static struct sig_fd *
sig_fd_alloc_insert (struct thread_group *group, int32_t fd,
		     const struct eri_sigset *mask, int32_t flags)
{
  struct sig_fd *sig_fd = eri_assert_mtmalloc (group->pool, sizeof *sig_fd);
  sig_fd->fd = fd;
  sig_fd->mask = eri_assert_mtmalloc (group->pool, sizeof *sig_fd->mask);
  sig_fd->mask->ref_count = 1;
  sig_fd->mask->lock = 0;
  sig_fd->mask->mask = *mask;
  sig_fd->flags = flags;
  sig_fd_rbt_insert (group, sig_fd);
  return sig_fd;
}

static struct sig_fd *
sig_fd_copy_insert (struct thread_group *group, int32_t fd,
		    const struct sig_fd *sig_fd)
{
  return sig_fd_alloc_insert (group, fd, &sig_fd->mask->mask, sig_fd->flags);
}

static void
sig_fd_remove_free (struct thread_group *group, struct sig_fd *fd)
{
  sig_fd_rbt_remove (group, fd);
  if (! eri_atomic_dec_fetch_rel (&fd->mask->ref_count))
    eri_assert_mtfree (group->pool, fd->mask);
  eri_assert_mtfree (group->pool, fd);
}

static struct sig_fd *
sig_fd_try_lock (struct thread_group *group, int32_t fd)
{
  eri_lock (&group->sig_fd_lock);
  struct sig_fd *sig_fd = sig_fd_rbt_get (group, &fd, ERI_RBT_EQ);
  if (! sig_fd) eri_unlock (&group->sig_fd_lock);
  return sig_fd;
}

static uint8_t
internal (struct thread_group *group, uint64_t addr)
{
  return (addr >= group->map_start && addr < group->map_end)
	 || (addr >= group->buf_start && addr < group->buf_end);
}

static uint8_t
internal_range (struct thread_group *group, uint64_t start, uint64_t size)
{
  uint64_t map_start = group->map_start;
  uint64_t map_end = group->map_end;
  uint64_t buf_start = group->buf_start;
  uint64_t buf_end = group->buf_end;
  uint64_t end = start + size;

  return (end > map_start && start < map_end)
	 || (end > buf_start && start < buf_end);
}

static uint8_t
copy_from_user (struct eri_live_thread *th,
		void *dst, const void *src, uint64_t size)
{
  if (! src) return 0;
  if (internal_range (th->group, (uint64_t) src, size)) return 0;
  return do_copy_from_user (th->ctx, dst, src, size);
}

static uint8_t
copy_to_user (struct eri_live_thread *th,
	      void *dst, const void *src, uint64_t size)
{
  if (! dst) return 0;
  if (internal_range (th->group, (uint64_t) dst, size)) return 0;
  return do_copy_to_user (th->ctx, dst, src, size);
}

static uint8_t
user_on_sig_stack (struct eri_live_thread *th, uint64_t rsp)
{
  struct eri_stack *stack = &th->sig_alt_stack;
  return ! (stack->flags & ERI_SS_AUTODISARM)
	 && rsp > stack->sp && rsp <= stack->sp + stack->size; 
}

static struct thread_group *
create_group (struct eri_live_signal_thread *sig_th,
	      struct eri_rtld_args *rtld_args)
{
  /* XXX: parameterize */
  uint64_t atomic_table_size =  2 * 1024 * 1024;
  const struct eri_common_args *common_args
			= eri_live_signal_thread__get_args (sig_th);
  uint64_t stack_size = common_args->stack_size;

  struct eri_mtpool *pool = eri_live_signal_thread__get_pool (sig_th);
  struct thread_group *group = eri_assert_mtmalloc (pool, sizeof *group);
  group->pool = pool;
  group->map_start = rtld_args->map_start;
  group->map_end = rtld_args->map_end;
  group->buf_start = common_args->buf;
  group->buf_end = common_args->buf + common_args->buf_size;
  group->ref_count = 0;
  group->pid = 0;

  group->sig_fd_lock = 0;
  ERI_RBT_INIT_TREE (sig_fd, group);

  group->atomic_table = eri_assert_mtmalloc (pool,
		atomic_table_size * sizeof *group->atomic_table);
  group->atomic_table_size = atomic_table_size;

  group->th_id = 0;
  group->stack_size = stack_size;

  return group;
}

static void
sig_set_frame (struct thread_context *th_ctx, struct eri_sigframe *frame)
{
  eri_assert (((uint64_t) frame & 1) == 0);
  /*
   * Set to 1 when null so:
   * 1. the low 32-bit is unique to ensure the futex,
   * 2. loop sig_return works (see SIG_RETURN in live-thread.S).
   */
  th_ctx->sig_frame = frame ? : (void *) 1;
}

static struct eri_sigframe *
sig_get_frame (struct thread_context *th_ctx)
{
  return (void *) ((uint64_t) th_ctx->sig_frame & ~1);
}

static uint8_t
sig_wait_frame (struct thread_context *th_ctx,
		const struct eri_timespec *timeout)
{
  return eri_assert_sys_futex_wait (&th_ctx->sig_frame, 1, timeout);
}

static struct thread_context *
create_context (struct eri_mtpool *pool, struct eri_live_thread *th)
{
  uint64_t text = (uint64_t) thread_context_text;
  uint64_t text_entry = (uint64_t) thread_context_text_entry;
  uint64_t text_return = (uint64_t) thread_context_text_return;
  uint64_t text_end = (uint64_t) thread_context_text_end;
  uint64_t text_size = text_end - text;

  uint64_t th_ctx_size16 = eri_size_of (struct thread_context, 16);
  struct thread_context *th_ctx
	 = eri_assert_mtmalloc (pool, th_ctx_size16 + text_size);

  uint64_t th_text = (uint64_t) th_ctx + th_ctx_size16;
  eri_memcpy ((uint8_t *) th_text, (uint8_t *) text, text_size);

  th_ctx->ext.zero = 0;
  th_ctx->ext.entry = th_text + text_entry - text;

  th_ctx->entry = (uint64_t) entry;
  th_ctx->ret = th_text + text_return - text;
  th_ctx->top = (uint64_t) th->stack + th->group->stack_size;
  th_ctx->sig_force_deliver = 0;
  sig_set_frame (th_ctx, 0);
  th_ctx->access = 0;
  th_ctx->syscall.swallow_single_step = 0;
  th_ctx->syscall.wait_sig = 0;
  th_ctx->atomic.access_end = 0;
  th_ctx->th = th;
  return th_ctx;
}

static struct eri_live_thread *
create (struct thread_group *group, struct eri_live_signal_thread *sig_th,
	int32_t *clear_tid)
{
  eri_atomic_inc (&group->ref_count);
  struct eri_live_thread *th
	= eri_assert_mtmalloc (group->pool, sizeof *th + group->stack_size);
  th->group = group;
  eri_debug ("%lx %lx\n", th, sig_th);
  th->sig_th = sig_th;
  th->id = eri_atomic_fetch_inc (&group->th_id);
  th->alive = 0;
  th->clear_tid = clear_tid;
  th->rec = eri_live_thread_recorder__create (group->pool, th->id);

  th->ctx = create_context (group->pool, th);
  return th;
}

struct eri_live_thread *
eri_live_thread__create_main (struct eri_live_signal_thread *sig_th,
			      struct eri_rtld_args *rtld_args)
{
  struct thread_group *group = create_group (sig_th, rtld_args);
  struct eri_live_thread *th = create (group, sig_th, 0);
  th->alive = 1;
  struct thread_context *th_ctx = th->ctx;
  th_ctx->ext.op.sig_hand = SIG_HAND_ASYNC;
  th_ctx->ext.op.args = 0;
  th_ctx->ext.op.code = _ERS_OP_SYSCALL;
  th_ctx->ext.ret = rtld_args->rip;
  th_ctx->rsp = rtld_args->rsp;
  th_ctx->sregs.rdx = rtld_args->rdx;
  eri_assert_syscall (sigaltstack, 0, &th->sig_alt_stack);
  return th;
}

struct thread_context *
start (struct eri_live_thread *th)
{
  eri_debug ("%lx %lx %lx %lx\n",
	     th, th->ctx, th->ctx->sig_frame, th->ctx->top);
  eri_assert_syscall (prctl, ERI_PR_SET_PDEATHSIG, ERI_SIGKILL);
  eri_assert (eri_assert_syscall (getppid)
	      == eri_live_signal_thread__get_pid (th->sig_th));

  eri_live_signal_thread__init_thread_sig_stack (
	th->sig_th, th->sig_stack, 2 * THREAD_SIG_STACK_SIZE);
  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_GS, th->ctx);

  eri_assert_sys_futex_wait (&th->alive, 0, 0);
  eri_debug ("leave %lx %lx\n",
	     __builtin_return_address (0), th->ctx->sig_frame);
  return th->ctx;
}

void
eri_live_thread__clone_main (struct eri_live_thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  struct eri_sys_clone_args args = {

    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID
    | ERI_SIGCHLD,

    (void *) th_ctx->top, &th->tid, &th->alive, 0, main, th_ctx
  };

  th->group->pid = eri_assert_sys_clone (&args);
}

#define SIG_ACT_TERM	((void *) 1)
#define SIG_ACT_CORE	((void *) 2)
#define SIG_ACT_STOP	((void *) 3)

#define SIG_ACT_INTERNAL_ACT(act) \
  ((act) == SIG_ACT_TERM || (act) == SIG_ACT_CORE || (act) == SIG_ACT_STOP)

uint8_t
eri_live_thread__sig_digest_act (
		struct eri_live_thread *th, const struct eri_siginfo *info,
		struct eri_sigaction *act)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  int32_t sig = info->sig;

  if (eri_si_sync (info)
      /*
       * Though this function can be called in different async contexts,
       * This can only happen synchronizly regards to the sig_mask.
       */
      && (eri_sig_set_set (eri_live_signal_thread__get_sig_mask (sig_th), sig)
	  || act->act == ERI_SIG_IGN))
    act->act = ERI_SIG_DFL;

  if (act->act == ERI_SIG_IGN)
    act->act = 0;
  else if (act->act == ERI_SIG_DFL)
    {
      if (sig == ERI_SIGCHLD || sig == ERI_SIGCONT
	  || sig == ERI_SIGURG || sig == ERI_SIGWINCH)
	act->act = 0;
      else if (sig == ERI_SIGHUP || sig == ERI_SIGINT || sig == ERI_SIGKILL
	       || sig == ERI_SIGPIPE || sig == ERI_SIGALRM
	       || sig == ERI_SIGTERM || sig == ERI_SIGUSR1
	       || sig == ERI_SIGUSR2 || sig == ERI_SIGIO
	       || sig == ERI_SIGPROF || sig == ERI_SIGVTALRM
	       || sig == ERI_SIGSTKFLT || sig == ERI_SIGPWR
	       || (sig >= ERI_SIGRTMIN && sig <= ERI_SIGRTMAX))
	act->act = SIG_ACT_TERM;
      else if (sig == ERI_SIGQUIT || sig == ERI_SIGILL || sig == ERI_SIGABRT
	       || sig == ERI_SIGFPE || sig == ERI_SIGSEGV || sig == ERI_SIGBUS
	       || sig == ERI_SIGSYS || sig == ERI_SIGTRAP
	       || sig == ERI_SIGXCPU || sig == ERI_SIGXFSZ)
	act->act = SIG_ACT_CORE;
      else if (sig == ERI_SIGTSTP || sig == ERI_SIGTTIN || sig == ERI_SIGTTOU)
	act->act = SIG_ACT_STOP;
      else eri_assert (0);
    }

  struct eri_sigset *force = th->ctx->sig_force_deliver;
  return act->act || (force && eri_sig_set_set (force, sig));
}

static void
disable_sig_stack (struct eri_stack *stack)
{
  stack->sp = 0;
  stack->flags = ERI_SS_DISABLE;
  stack->size = 0;
}

static uint8_t
sig_setup_user_frame (struct eri_live_thread *th, struct eri_sigframe *frame)
{
  eri_debug ("\n");
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;

  struct eri_sigaction *act = &th_ctx->sig_act;
  struct eri_stack *stack = &th->sig_alt_stack;

  struct eri_ucontext *ctx = &frame->ctx;

  uint8_t alt = (act->flags & ERI_SA_ONSTACK)
		&& ! user_on_sig_stack (th, ctx->mctx.rsp);
  uint64_t rsp = alt ? stack->sp + stack->size : ctx->mctx.rsp - 128;
  eri_debug ("%lx %u %lx\n", rsp, alt, ctx->mctx.rsp);

  uint64_t top = (uint64_t) th->sig_stack + 2 * THREAD_SIG_STACK_SIZE;

  eri_assert ((uint64_t) frame >= top - THREAD_SIG_STACK_SIZE
	      && (uint64_t) frame < top);

  ctx->stack = *stack;
  if (stack->flags & ERI_SS_AUTODISARM) disable_sig_stack (stack);

  ctx->sig_mask = *eri_live_signal_thread__get_sig_mask (sig_th);

  /* XXX: default restorer */
  frame->restorer = act->flags & ERI_SA_RESTORER ? act->restorer : 0;

  if (ctx->mctx.fpstate)
    {
      uint32_t fpstate_size = ctx->mctx.fpstate->size;
      rsp = eri_round_down (rsp - fpstate_size, 64);
      if (! copy_to_user (th, (void *) rsp, ctx->mctx.fpstate, fpstate_size))
	{
	  frame->info.sig = ERI_SIGSEGV;
	  return 0;
	}
      ctx->mctx.fpstate = (void *) rsp;
    }

  struct eri_sigframe *user_frame
	= (void *) (eri_round_down (rsp - sizeof *user_frame, 16) - 8);
  if (! copy_to_user (th, user_frame, frame, sizeof *user_frame))
    {
      frame->info.sig = ERI_SIGSEGV;
      return 0;
    }

  th_ctx->sig_act_frame = user_frame;
  eri_debug ("leave\n");
  return 1;
}

eri_noreturn void
sig_action (struct eri_live_thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  struct eri_sigframe *frame = sig_get_frame (th_ctx);
  sig_set_frame (th_ctx, 0);
  eri_assert (frame->info.sig);

  eri_debug ("%lx\n", frame);

  struct eri_live_signal_thread *sig_th = th->sig_th;

  uint64_t core_status = 139;

  /* XXX: core, die context */
  if (frame->info.sig == ERI_LIVE_SIGNAL_THREAD_SIG_EXIT_GROUP)
    {
      eri_live_signal_thread__die (sig_th);
      eri_assert_sys_thread_die (&th->alive);
    }

  eri_atomic_store (&th_ctx->ext.op.sig_hand, SIG_HAND_SIG_ACTION);

  if (! SIG_ACT_INTERNAL_ACT (th_ctx->sig_act.act))
    {
      if (th_ctx->ext.op.code == _ERS_OP_SYSCALL)
	th_ctx->syscall.swallow_single_step = 0;

      if (! sig_setup_user_frame (th, frame)) goto core;

      struct eri_stack st = {
	(uint64_t) th->sig_stack, 0, 2 * THREAD_SIG_STACK_SIZE
      };
      eri_assert_syscall (sigaltstack, &st, 0);

      eri_live_signal_thread__sig_reset (sig_th, &th_ctx->sig_act.mask);
      sig_act (th_ctx);
    }

  if (th_ctx->sig_act.act == SIG_ACT_STOP)
    {
      /* TODO: stop */

      struct eri_sigframe *act_frame = (void *) th->stack;
      act_frame->ctx.mctx = frame->ctx.mctx;
      act_frame->restorer = eri_assert_sys_sigreturn;
      th_ctx->sig_act_frame = act_frame;
      eri_live_signal_thread__sig_reset (sig_th, 0);
      sig_return (frame);
    }

  if (th_ctx->sig_act.act == SIG_ACT_TERM) core_status = 130;

  struct eri_sigset mask;
core:
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);
  eri_live_signal_thread__sig_reset (sig_th, &mask);
  eri_debug ("core\n");
  if (eri_live_signal_thread__exit (sig_th, 1, core_status))
    {
      if (core_status == 130) eri_assert_syscall (exit, 0);
      eri_assert_unreachable ();
    }
  else
    {
      eri_live_signal_thread__die (sig_th);
      eri_assert_sys_thread_die (&th->alive);
    }
}

static void
sig_set (struct thread_context *th_ctx, struct eri_sigframe *frame,
	 const struct eri_sigaction *act, uint8_t sig_hand)
{
  sig_set_frame (th_ctx, frame);
  th_ctx->sig_act = *act;

  th_ctx->ext.op.sig_hand = sig_hand;
  frame->ctx.stack.size -= THREAD_SIG_STACK_SIZE;
}

static void
sig_return_to (struct eri_live_thread *th,
	       struct eri_ucontext *ctx, void *fn)
{
  struct thread_context *th_ctx = th->ctx;
  uint64_t *stack = (void *) th_ctx->top;
  *--stack = 0; /* XXX: cfi */
  *--stack = (uint64_t) fn;
  *--stack = (uint64_t) th;

  *--stack = ctx->mctx.rflags;
  *--stack = ctx->mctx.rsp;
  *--stack = ctx->mctx.rip;
  *--stack = (uint64_t) ctx;

  ctx->mctx.rflags = 0;
  ctx->mctx.rsp = (uint64_t) stack;
  ctx->mctx.rip = (uint64_t) sig_to;
}

static uint8_t
sig_access_fault (struct thread_context *th_ctx,
		  struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (eri_si_sync (info)
      && (info->sig == ERI_SIGSEGV || info->sig == ERI_SIGBUS)
      && ctx->mctx.rip == th_ctx->access)
    {
      ctx->mctx.rip = th_ctx->access_fault;
      return 1;
    }

  return 0;
}

static uint8_t
sig_prepare_sync (struct eri_live_thread *th, struct eri_siginfo *info,
		  struct eri_sigaction *act)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  eri_live_signal_thread__sig_prepare_sync (sig_th, info, act);

  if (! eri_si_sync (info)) return 1;

  return eri_live_thread__sig_digest_act (th, info, act);
}

static void
sig_hand_async (struct eri_live_thread *th, struct eri_sigframe *frame,
		struct eri_sigaction *act)
{
  eri_debug ("\n");

  struct eri_siginfo *info = &frame->info;

  if (eri_si_single_step (info)) return;
  eri_assert (! eri_si_sync (info));

  sig_set (th->ctx, frame, act, SIG_HAND_NONE);
}

static void
sig_hand_none (struct eri_live_thread *th, struct eri_sigframe *frame,
	       struct eri_sigaction *act)
{
  eri_assert (eri_si_single_step (&frame->info));
}

static void
sig_hand_sig_action (struct eri_live_thread *th, struct eri_sigframe *frame,
		     struct eri_sigaction *act)
{
  struct thread_context *th_ctx = th->ctx;

  struct eri_siginfo *info = &frame->info;
  struct eri_ucontext *ctx = &frame->ctx;

  if (internal (th->group, ctx->mctx.rip))
    {
      if (sig_access_fault (th_ctx, info, ctx)) return;
      if (eri_si_single_step (info)) return;
      eri_assert (! eri_si_sync (info));

      if (th_ctx->sig_act.act == SIG_ACT_STOP)
	ctx->mctx = th_ctx->sig_act_frame->ctx.mctx;
      else
	{
	  ctx->mctx.rip = (uint64_t) th_ctx->sig_act.act;
	  ctx->mctx.rsp = (uint64_t) th_ctx->sig_act_frame;
	  ctx->mctx.rax = 0;
	  ctx->mctx.rdi = th_ctx->sig_act_frame->info.sig;
	  ctx->mctx.rsi = (uint64_t) &th_ctx->sig_act_frame->info;
	  ctx->mctx.rdx = (uint64_t) &th_ctx->sig_act_frame->ctx;
	}
    }

  /* XXX: merge sig_prepare_sync & sig_reset */
  if (eri_si_sync (info) && ! sig_prepare_sync (th, info, act))
    return;

  sig_set (th_ctx, frame, act, SIG_HAND_NONE);
  sig_return_to (th, ctx, sig_action);
}

static void
sig_hand_return_to_user (
		struct eri_live_thread *th, struct eri_sigframe *frame,
		struct eri_sigaction *act)
{
  struct eri_siginfo *info = &frame->info;
  struct eri_ucontext *ctx = &frame->ctx;

  uint8_t intern = internal (th->group, ctx->mctx.rip);

  struct thread_context *th_ctx = th->ctx;
  if (intern && eri_si_single_step (info)
      && th_ctx->ext.op.code == _ERS_OP_SYSCALL)
    th_ctx->syscall.swallow_single_step = 1;

  if (intern && eri_si_single_step (info)) return;

  if (th_ctx->ext.op.code == _ERS_OP_SYSCALL
      && th_ctx->syscall.swallow_single_step
      && ctx->mctx.rip == th_ctx->ext.ret && eri_si_single_step (info))
    {
      th_ctx->syscall.swallow_single_step = 0;
      return;
    }

  if (intern)
    {
      /* May happen when we are setting up sig alt stack.  */
      if (sig_access_fault (th_ctx, info, ctx)) return;
      eri_assert (! eri_si_sync (info));
    }

  if (eri_si_sync (info) && ! sig_prepare_sync (th, info, act))
    return;

  if (intern)
    {
      ctx->mctx.rcx = th_ctx->sregs.rcx;
      ctx->mctx.rbx = th_ctx->ext.rbx;
      ctx->mctx.rip = th_ctx->ext.ret;
    }

  sig_set (th_ctx, frame, act, SIG_HAND_NONE);
  sig_return_to (th, ctx, sig_action);
}

static void
sig_restart_set_ctx (struct thread_context *th_ctx)
{
  struct eri_ucontext *ctx = &sig_get_frame (th_ctx)->ctx;

  ctx->mctx.rbx = th_ctx->ext.rbx;
  ctx->mctx.rip = th_ctx->ext.call;

  ctx->mctx.rsp = th_ctx->rsp;

  ctx->mctx.rax = th_ctx->sregs.rax;
  ctx->mctx.rdi = th_ctx->sregs.rdi;
  ctx->mctx.rsi = th_ctx->sregs.rsi;
  ctx->mctx.rdx = th_ctx->sregs.rdx;
  ctx->mctx.rcx = th_ctx->sregs.rcx;
  ctx->mctx.r8 = th_ctx->sregs.r8;
  ctx->mctx.r9 = th_ctx->sregs.r9;
  ctx->mctx.r10 = th_ctx->sregs.r10;
  ctx->mctx.r11 = th_ctx->sregs.r11;
  ctx->mctx.rflags = th_ctx->sregs.rflags;
}

struct eri_live_thread__create_args
{
  struct eri_live_thread *pth;
  struct eri_live_thread *cth;
};

struct eri_live_thread *
eri_live_thread__create (struct eri_live_signal_thread *sig_th,
			 struct eri_live_thread__create_args *create_args)
{
  struct eri_live_thread *pth = create_args->pth;
  struct thread_context *pth_ctx = pth->ctx;

  int32_t flags = pth_ctx->sregs.rdi;
  int32_t *ctid = (void *) pth_ctx->sregs.r10;
  int32_t *clear_tid = flags & ERI_CLONE_CHILD_CLEARTID ? ctid : 0;
  struct eri_live_thread *th = create (pth->group, sig_th, clear_tid);

  create_args->cth = th;
  struct thread_context *th_ctx = th->ctx;
  th_ctx->ext.op = pth_ctx->ext.op;
  th_ctx->ext.rbx = pth_ctx->ext.rbx;
  th_ctx->ext.ret = pth_ctx->ext.ret;
  th_ctx->rsp = pth_ctx->sregs.rsi;
  th_ctx->sregs = pth_ctx->sregs;
  th_ctx->sregs.rax = 0;
  th_ctx->sregs.rcx = th_ctx->ext.ret;
  th_ctx->sregs.r11 = th_ctx->sregs.rflags;
  th_ctx->syscall.eregs = pth_ctx->syscall.eregs;
  *(uint64_t *) (th_ctx->top - 8) = *(uint64_t *) (pth_ctx->top - 8);
  eri_debug ("%lx %lx\n", th_ctx->top, *(uint64_t *) (th_ctx->top - 8));
  th->sig_alt_stack = pth->sig_alt_stack;
  return th;
}

uint64_t
eri_live_thread__clone (struct eri_live_thread *th)
{
  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  struct thread_context *th_ctx = th->ctx;
  void *new_tls = (void *) th_ctx->sregs.r8;
  struct eri_sys_clone_args args = {

    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_THREAD
    | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID
    | (new_tls ? ERI_CLONE_SETTLS : 0),

    (void *) (th_ctx->top - 8),
    &th->tid, &th->alive, new_tls, start, th
  };

  eri_debug ("clone %lx\n", args.stack);
  uint64_t res = eri_sys_clone (&args);

  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  return res;
}

static uint64_t
hash (uint64_t x)
{
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
  x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
  x = x ^ (x >> 31);
  return x;
}

static uint64_t
do_lock_atomic (struct thread_group *group, uint64_t addr)
{
  uint64_t idx = hash (addr & ~0xf) % group->atomic_table_size;

  uint32_t i = 0;
  while (eri_atomic_bit_test_set (group->atomic_table + idx, 0))
    if (++i % 16 == 0) eri_assert_syscall (sched_yield);
  eri_barrier ();
  return idx;
}

static struct atomic_pair
lock_atomic (struct thread_group *group, uint64_t addr, uint8_t size)
{
  struct atomic_pair idx = { do_lock_atomic (group, addr) };
  idx.second = (addr & ~0xf) != ((addr + size - 1) & ~0xf)
		 ? do_lock_atomic (group, addr + size - 1) : idx.first;
  return idx;
}

static void
do_unlock_atomic (struct thread_group *group, uint64_t idx)
{
  eri_barrier ();
  eri_atomic_and (group->atomic_table + idx, -2);
}

static struct atomic_pair
unlock_atomic (struct thread_group *group, struct atomic_pair *idx,
	       uint8_t update)
{
  uint8_t aligned = idx->first == idx->second;
  if (update)
    {
      group->atomic_table[idx->first] += 2;
      if (! aligned) group->atomic_table[idx->second] += 2;
    }

  struct atomic_pair ver = {
    group->atomic_table[idx->first] >> 1,
    group->atomic_table[idx->second] >> 1
  };

  do_unlock_atomic (group, idx->first);
  if (! aligned) do_unlock_atomic (group, idx->second);
  return ver;
}

static void
clear_tid_sigsegv_handler (struct eri_siginfo *info,
			   struct eri_ucontext *ctx)
{
  extern uint8_t clear_tid_clear_user[];
  extern uint8_t clear_tid_clear_user_fault[];
  eri_assert (ctx->mctx.rip == (uint64_t) clear_tid_clear_user);
  ctx->mctx.rip = (uint64_t) clear_tid_clear_user_fault;
}

struct clear_tid_args
{
  struct eri_live_thread *th;
  int32_t lock;
};

static void
clear_tid (void *args)
{
  struct clear_tid_args *a = args;
  struct eri_live_thread *th = a->th;
  struct thread_group *group = th->group;
  int32_t *clear_tid = th->clear_tid;

  struct atomic_pair idx
	= lock_atomic (group, (uint64_t) clear_tid, sizeof *clear_tid);

  uint8_t fault = 0;
  asm ("clear_tid_clear_user:\n"
       "  movl\t$0, %0\n"
       "  jmp\t1f\n"
       "clear_tid_clear_user_fault:\n"
       "  movb\t$1, %b1\n"
       "1:" : "=m" (*clear_tid), "+r" (fault));
  if (! fault)
    {
      struct atomic_pair ver = unlock_atomic (group, &idx, 0);
      eri_live_thread_recorder__rec_atomic (th->rec, &ver.first);
      eri_syscall (futex, clear_tid, ERI_FUTEX_WAKE, 1);
    }
  else unlock_atomic (group, &idx, 0);

  eri_unlock (&a->lock);
}

static void
destroy_context (struct eri_mtpool *pool, struct thread_context *ctx)
{
  eri_assert_mtfree (pool, ctx);
}

void
eri_live_thread__destroy (struct eri_live_thread *th,
			  struct eri_helper *helper)
{
  if (helper && th->clear_tid)
    {
      struct clear_tid_args args = { th, 1 };
      eri_helper__invoke (helper, clear_tid, &args,
			  clear_tid_sigsegv_handler);
      eri_lock (&args.lock);
    }

  struct thread_group *group = th->group;
  struct eri_mtpool *pool = group->pool;

  destroy_context (pool, th->ctx);
  eri_live_thread_recorder__destroy (th->rec);
  eri_assert_mtfree (pool, th);

  eri_barrier ();
  if (eri_atomic_dec_fetch (&group->ref_count)) return;

  struct sig_fd *fd, *nfd;
  ERI_RBT_FOREACH_SAFE (sig_fd, group, fd, nfd)
    sig_fd_remove_free (group, fd);

  eri_assert_mtfree (pool, group->atomic_table);
  eri_assert_mtfree (pool, group);
}

void
eri_live_thread__join (struct eri_live_thread *th)
{
  eri_lock (&th->alive);
}

#define SYSCALL_DONE			0
#define SYSCALL_SIG_WAIT_RESTART	1
#define SYSCALL_SEG_FAULT		2

#define SYSCALL_RETURN_DONE(th_ctx, result) \
  do {									\
    (th_ctx)->sregs.rax = result;					\
    return SYSCALL_DONE;						\
  } while (0)

#define DEFINE_SYSCALL(name) \
static uint32_t								\
ERI_PASTE (syscall_, name) (struct eri_live_thread *th)

#define SYSCALL_TO_IMPL(name) \
  DEFINE_SYSCALL (name) { SYSCALL_RETURN_DONE (th->ctx, ERI_ENOSYS); }

static uint64_t
syscall_set_sig_alt_stack (struct eri_live_thread *th,
			   struct eri_stack *stack)
{
  if (user_on_sig_stack (th, th->ctx->rsp))
    return ERI_EPERM;

  int32_t flags = stack->flags & ERI_SS_FLAG_BITS;
  int32_t mode = stack->flags & ~ERI_SS_FLAG_BITS;
  if (mode != ERI_SS_DISABLE && mode != ERI_SS_ONSTACK && mode != 0)
    return ERI_EINVAL;

  if (mode == ERI_SS_DISABLE)
    disable_sig_stack (stack);
  else
    {
      if (stack->size < ERI_MINSIGSTKSZ)
	return ERI_ENOMEM;

      stack->flags = flags;
    }

  th->sig_alt_stack = *stack;
  return 0;
}

static uint32_t
syscall_signal_thread (struct eri_live_thread *th)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;
  struct eri_sys_syscall_args args = {
    th_ctx->sregs.rax,
    { th_ctx->sregs.rdi, th_ctx->sregs.rsi, th_ctx->sregs.rdx,
      th_ctx->sregs.r10, th_ctx->sregs.r8, th_ctx->sregs.r9 }
  };
  eri_live_signal_thread__syscall (sig_th, &args);
  SYSCALL_RETURN_DONE (th_ctx, args.result);
}

static uint8_t
syscall_sig_wait (struct thread_context *th_ctx,
		  const struct eri_timespec *timeout)
{
  eri_atomic_store (&th_ctx->syscall.wait_sig, 1);
  eri_barrier ();
  uint8_t res = sig_wait_frame (th_ctx, timeout);
  th_ctx->syscall.wait_sig = 0;
  return res;
}

DEFINE_SYSCALL (clone)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;

  int32_t flags = th_ctx->sregs.rdi;
  int32_t *ptid = (void *) th_ctx->sregs.rdx;
  int32_t *ctid = (void *) th_ctx->sregs.r10;
  /* XXX: support more */
  eri_assert (flags == ERI_CLONE_SUPPORTED_FLAGS);

  struct eri_live_thread__create_args create_args = { th };
  struct eri_live_signal_thread__clone_args args = { &create_args };

  if (! eri_live_signal_thread__clone (sig_th, &args))
    return SYSCALL_SIG_WAIT_RESTART;

  if (! eri_syscall_is_error (args.result))
    {
      if (flags & ERI_CLONE_PARENT_SETTID)
	copy_to_user (th, ptid, &args.tid, sizeof args.tid);
      if (flags & ERI_CLONE_CHILD_SETTID)
	copy_to_user (th, ctid, &args.tid, sizeof args.tid);
      eri_assert_sys_futex_wake (&create_args.cth->alive, 1);

      SYSCALL_RETURN_DONE (th_ctx, args.tid);
    }
  else SYSCALL_RETURN_DONE (th_ctx, args.result);
}

SYSCALL_TO_IMPL (unshare)
SYSCALL_TO_IMPL (kcmp)
SYSCALL_TO_IMPL (fork)
SYSCALL_TO_IMPL (vfork)
SYSCALL_TO_IMPL (setns)

DEFINE_SYSCALL (set_tid_address)
{
  struct thread_context *th_ctx = th->ctx;
  th->clear_tid = (void *) th_ctx->sregs.rdi;
  SYSCALL_RETURN_DONE (th_ctx, 0);
}

static uint32_t
syscall_do_exit (struct eri_live_thread *th)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;
  int32_t nr = th_ctx->sregs.rax;
  uint8_t exit_group = nr == __NR_exit_group;
  int32_t status = th_ctx->sregs.rdi;

  if (! eri_live_signal_thread__exit (sig_th, exit_group, status))
    return SYSCALL_SIG_WAIT_RESTART;

  eri_debug ("syscall exit\n");
  eri_assert_sys_exit_nr (nr, 0);
}

DEFINE_SYSCALL (exit) { return syscall_do_exit (th); }
DEFINE_SYSCALL (exit_group) { return syscall_do_exit (th); }

SYSCALL_TO_IMPL (wait4)
SYSCALL_TO_IMPL (waitid)

SYSCALL_TO_IMPL (execve)
SYSCALL_TO_IMPL (execveat)
SYSCALL_TO_IMPL (ptrace)
SYSCALL_TO_IMPL (syslog)
SYSCALL_TO_IMPL (seccomp)

SYSCALL_TO_IMPL (uname)
SYSCALL_TO_IMPL (sysinfo)
SYSCALL_TO_IMPL (getcpu)
SYSCALL_TO_IMPL (getrandom)

SYSCALL_TO_IMPL (setuid)
SYSCALL_TO_IMPL (getuid)
SYSCALL_TO_IMPL (setgid)
SYSCALL_TO_IMPL (getgid)
SYSCALL_TO_IMPL (geteuid)
SYSCALL_TO_IMPL (getegid)

DEFINE_SYSCALL (gettid)
{
  SYSCALL_RETURN_DONE (th->ctx, eri_live_signal_thread__get_tid (th->sig_th));
}

DEFINE_SYSCALL (getpid)
{
  SYSCALL_RETURN_DONE (th->ctx, eri_live_signal_thread__get_pid (th->sig_th));
}

DEFINE_SYSCALL (getppid) { return syscall_signal_thread (th); }

SYSCALL_TO_IMPL (setreuid)
SYSCALL_TO_IMPL (setregid)

SYSCALL_TO_IMPL (setresuid)
SYSCALL_TO_IMPL (getresuid)
SYSCALL_TO_IMPL (setresgid)
SYSCALL_TO_IMPL (getresgid)

SYSCALL_TO_IMPL (setfsuid)
SYSCALL_TO_IMPL (setfsgid)

SYSCALL_TO_IMPL (setgroups)
SYSCALL_TO_IMPL (getgroups)

SYSCALL_TO_IMPL (setsid)
SYSCALL_TO_IMPL (getsid)
SYSCALL_TO_IMPL (setpgid)
SYSCALL_TO_IMPL (getpgid)
SYSCALL_TO_IMPL (getpgrp)

SYSCALL_TO_IMPL (settimeofday)
SYSCALL_TO_IMPL (gettimeofday)
SYSCALL_TO_IMPL (time)
SYSCALL_TO_IMPL (times)
SYSCALL_TO_IMPL (adjtimex)

SYSCALL_TO_IMPL (clock_settime)
SYSCALL_TO_IMPL (clock_gettime)
SYSCALL_TO_IMPL (clock_getres)
SYSCALL_TO_IMPL (clock_nanosleep)
SYSCALL_TO_IMPL (clock_adjtime)

SYSCALL_TO_IMPL (nanosleep)

SYSCALL_TO_IMPL (alarm)
SYSCALL_TO_IMPL (setitimer)
SYSCALL_TO_IMPL (getitimer)

SYSCALL_TO_IMPL (timer_create)
SYSCALL_TO_IMPL (timer_settime)
SYSCALL_TO_IMPL (timer_gettime)
SYSCALL_TO_IMPL (timer_getoverrun)
SYSCALL_TO_IMPL (timer_delete)

SYSCALL_TO_IMPL (setrlimit)
SYSCALL_TO_IMPL (getrlimit)
SYSCALL_TO_IMPL (prlimit64)
SYSCALL_TO_IMPL (getrusage)

SYSCALL_TO_IMPL (capset)
SYSCALL_TO_IMPL (capget)

SYSCALL_TO_IMPL (personality)
SYSCALL_TO_IMPL (prctl)

DEFINE_SYSCALL (arch_prctl)
{
  struct thread_context *th_ctx = th->ctx;
  int32_t code = th_ctx->sregs.rdi;
  void *user_addr = (void *) th_ctx->sregs.rsi;

  eri_debug ("user_addr %lx\n", user_addr);
  /* XXX: warning for set gs */
  if (code == ERI_ARCH_SET_FS || code == ERI_ARCH_SET_GS)
    SYSCALL_RETURN_DONE (th_ctx,
			 eri_syscall (arch_prctl, code, user_addr));

  if (code == ERI_ARCH_GET_FS || code == ERI_ARCH_GET_GS)
    {
      uint64_t addr;
      eri_assert_syscall (arch_prctl, code, &addr);
      if (! copy_to_user (th, user_addr, &addr, sizeof *user_addr))
	SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);
      SYSCALL_RETURN_DONE (th_ctx, 0);
    }

  SYSCALL_RETURN_DONE (th_ctx, ERI_EINVAL);
}

SYSCALL_TO_IMPL (quotactl)
SYSCALL_TO_IMPL (acct)

SYSCALL_TO_IMPL (setpriority)
SYSCALL_TO_IMPL (getpriority)

DEFINE_SYSCALL (sched_yield)
{
  /* TODO: syscall */
  SYSCALL_RETURN_DONE (th->ctx, 0);
}

SYSCALL_TO_IMPL (sched_setparam)
SYSCALL_TO_IMPL (sched_getparam)
SYSCALL_TO_IMPL (sched_setscheduler)
SYSCALL_TO_IMPL (sched_getscheduler)
SYSCALL_TO_IMPL (sched_get_priority_max)
SYSCALL_TO_IMPL (sched_get_priority_min)
SYSCALL_TO_IMPL (sched_rr_get_interval)
SYSCALL_TO_IMPL (sched_setaffinity)
SYSCALL_TO_IMPL (sched_getaffinity)
SYSCALL_TO_IMPL (sched_setattr)
SYSCALL_TO_IMPL (sched_getattr)

SYSCALL_TO_IMPL (ioprio_set)
SYSCALL_TO_IMPL (ioprio_get)

DEFINE_SYSCALL (rt_sigprocmask)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;

  int32_t how = th_ctx->sregs.rdi;
  const struct eri_sigset *user_mask = (void *) th_ctx->sregs.rsi;
  struct eri_sigset *user_old_mask = (void *) th_ctx->sregs.rdx;
  uint64_t sig_set_size = th_ctx->sregs.r10;

  if ((how != ERI_SIG_BLOCK && how != ERI_SIG_UNBLOCK
       && how != ERI_SIG_SETMASK)
      || sig_set_size != ERI_SIG_SETSIZE)
    SYSCALL_RETURN_DONE (th_ctx, ERI_EINVAL);

  struct eri_sigset old_mask;
  if ((how == ERI_SIG_BLOCK || how == ERI_SIG_UNBLOCK) || user_old_mask)
    old_mask = *eri_live_signal_thread__get_sig_mask (sig_th);

  if (user_mask)
    {
      struct eri_sigset mask;
      if (! copy_from_user (th, &mask, user_mask, sizeof mask))
	SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);

      if (how == ERI_SIG_BLOCK)
	eri_sig_union_set (&mask, &old_mask);
      else if (how == ERI_SIG_UNBLOCK)
	{
	  eri_sig_diff_set (&old_mask, &mask);
	  mask = old_mask;
	}

      if (! eri_live_signal_thread__sig_mask_async (sig_th, &mask))
	return SYSCALL_SIG_WAIT_RESTART;

      if (eri_live_signal_thread__signaled (sig_th))
	syscall_sig_wait (th_ctx, 0);
    }

  if (user_old_mask
      && ! copy_to_user (th, user_old_mask, &old_mask,
			 sizeof *user_old_mask))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);

  SYSCALL_RETURN_DONE (th_ctx, 0);
}

DEFINE_SYSCALL (rt_sigaction)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;

  int32_t sig = th_ctx->sregs.rdi;
  const struct eri_sigaction *user_act = (void *) th_ctx->sregs.rsi;
  struct eri_sigaction *user_old_act = (void *) th_ctx->sregs.rdx;
  if (sig == 0 || sig >= ERI_NSIG
      || sig == ERI_SIGKILL || sig == ERI_SIGSTOP)
    SYSCALL_RETURN_DONE (th_ctx, ERI_EINVAL);

  if (! user_act && ! user_old_act)
    SYSCALL_RETURN_DONE (th_ctx, 0);

  struct eri_sigaction act;
  struct eri_sigaction old_act;

  if (user_act
      && ! copy_from_user (th, &act, user_act, sizeof act))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);

  if (! eri_live_signal_thread__sig_action (
	sig_th, sig, user_act ? &act : 0, user_old_act ? &old_act : 0))
    return SYSCALL_SIG_WAIT_RESTART;

  if (user_old_act
      && ! copy_to_user (th, user_old_act, &old_act,
			 sizeof *user_old_act))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);

  SYSCALL_RETURN_DONE (th_ctx, 0);
}

DEFINE_SYSCALL (sigaltstack)
{
  struct thread_context *th_ctx = th->ctx;

  const struct eri_stack *user_stack = (void *) th_ctx->sregs.rdi;
  struct eri_stack *user_old_stack = (void *) th_ctx->sregs.rsi;

  if (! user_stack && ! user_old_stack)
    SYSCALL_RETURN_DONE (th_ctx, 0);

  struct eri_stack stack;
  struct eri_stack old_stack;

  if (user_old_stack)
    {
      old_stack = th->sig_alt_stack;
      old_stack.flags |= user_on_sig_stack (th, th_ctx->rsp)
			   ? ERI_SS_ONSTACK : 0;
    }

  if (user_stack)
    {
      if (! copy_from_user (th, &stack, user_stack, sizeof stack))
	SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);

      uint64_t err = syscall_set_sig_alt_stack (th, &stack);
      if (err) SYSCALL_RETURN_DONE (th_ctx, err);
    }

  if (user_old_stack
      && ! copy_to_user (th, user_old_stack, &old_stack,
			 sizeof *user_old_stack))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);

  SYSCALL_RETURN_DONE (th_ctx, 0);
}

DEFINE_SYSCALL (rt_sigreturn)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;

  if (! eri_live_signal_thread__sig_mask_all (sig_th))
    return SYSCALL_SIG_WAIT_RESTART;

  const struct eri_sigframe *user_frame = (void *) (th_ctx->rsp - 8);

  uint64_t rsp = (uint64_t) th->stack + ERI_MINSIGSTKSZ;

  struct eri_sigframe frame;
  if (! copy_from_user (th, &frame, user_frame, sizeof frame))
    return SYSCALL_SEG_FAULT;

  struct eri_ucontext *ctx = &frame.ctx;
  if (ctx->mctx.fpstate)
    {
      const struct eri_fpstate *user_fpstate = ctx->mctx.fpstate;
      struct eri_fpstate fpstate;
      if (! copy_from_user (th, &fpstate, user_fpstate, sizeof fpstate))
	return SYSCALL_SEG_FAULT;
      if (fpstate.size + 64 + sizeof frame + 16 + 8 >= ERI_MINSIGSTKSZ)
	return SYSCALL_SEG_FAULT;

      rsp = eri_round_down (rsp - fpstate.size, 64);
      if (! copy_from_user (th, (void *) rsp, user_fpstate, fpstate.size))
	return SYSCALL_SEG_FAULT;

      ctx->mctx.fpstate = (void *) rsp;
    }

  eri_live_signal_thread__sig_reset (sig_th, &ctx->sig_mask);
  eri_sig_empty_set (&ctx->sig_mask);

  syscall_set_sig_alt_stack (th, &ctx->stack);
  ctx->stack.sp = (uint64_t) th->sig_stack;
  ctx->stack.flags = 0;
  ctx->stack.size = 2 * THREAD_SIG_STACK_SIZE;

  th_ctx->ext.rbx = ctx->mctx.rbx;
  th_ctx->ext.ret = ctx->mctx.rip;
  th_ctx->rsp = ctx->mctx.rsp;
  th_ctx->sregs.rax = ctx->mctx.rax;
  th_ctx->sregs.rdi = ctx->mctx.rdi;
  th_ctx->sregs.rsi = ctx->mctx.rsi;
  th_ctx->sregs.rdx = ctx->mctx.rdx;
  th_ctx->sregs.rcx = ctx->mctx.rcx;
  th_ctx->sregs.r8 = ctx->mctx.r8;
  th_ctx->sregs.r9 = ctx->mctx.r9;
  th_ctx->sregs.r10 = ctx->mctx.r10;
  th_ctx->sregs.r11 = ctx->mctx.r11;
  th_ctx->sregs.rflags = ctx->mctx.rflags;
  th_ctx->syscall.eregs.rbp = ctx->mctx.rbp;
  th_ctx->syscall.eregs.r12 = ctx->mctx.r12;
  th_ctx->syscall.eregs.r13 = ctx->mctx.r13;
  th_ctx->syscall.eregs.r14 = ctx->mctx.r14;
  th_ctx->syscall.eregs.r15 = ctx->mctx.r15;
  ctx->mctx.rflags = 0;

  frame.restorer = eri_assert_sys_sigreturn;

  struct eri_sigframe *stack
	= (void *) eri_round_down (rsp - sizeof *stack, 16) - 8;
  *stack = frame;

  sig_return_back (stack);
  return SYSCALL_DONE;
}

DEFINE_SYSCALL (rt_sigpending) { return syscall_signal_thread (th); }

static uint32_t
syscall_do_pause (struct eri_live_thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  syscall_sig_wait (th_ctx, 0);
  SYSCALL_RETURN_DONE (th_ctx, ERI_EINTR);
}

DEFINE_SYSCALL (pause) { return syscall_do_pause (th); }

DEFINE_SYSCALL (rt_sigsuspend)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;
  const struct eri_sigset *user_mask = (void *) th_ctx->sregs.rdi;
  uint64_t size = th_ctx->sregs.rsi;

  if (size != ERI_SIG_SETSIZE)
    SYSCALL_RETURN_DONE (th_ctx, ERI_EINVAL);

  struct eri_sigset mask;
  if (! copy_from_user (th, &mask, user_mask, sizeof mask))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);

  if (! eri_live_signal_thread__sig_tmp_mask_async (sig_th, &mask))
    return SYSCALL_SIG_WAIT_RESTART;

  return syscall_do_pause (th);
}

DEFINE_SYSCALL (rt_sigtimedwait)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;
  const struct eri_sigset *user_set = (void *) th_ctx->sregs.rdi;
  struct eri_siginfo *user_info = (void *) th_ctx->sregs.rsi;
  const struct eri_timespec *user_timeout = (void *) th_ctx->sregs.rdx;
  uint64_t size = th_ctx->sregs.r10;

  if (size != ERI_SIG_SETSIZE)
    SYSCALL_RETURN_DONE (th_ctx, ERI_EINVAL);

  struct eri_sigset set;
  if (! copy_from_user (th, &set, user_set, sizeof set))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);

  struct eri_timespec timeout;
  if (user_timeout
      && ! copy_from_user (th, &timeout, user_timeout, sizeof timeout))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);

  const struct eri_sigset *mask
	= eri_live_signal_thread__get_sig_mask (sig_th);

  struct eri_sigset tmp_mask = *mask;
  eri_sig_diff_set (&tmp_mask, &set);

  eri_sig_and_set (&set, mask);
  eri_atomic_store_rel (&th_ctx->sig_force_deliver, &set);

  eri_assert (eri_live_signal_thread__sig_tmp_mask_async (sig_th, &tmp_mask));

  if (! syscall_sig_wait (th_ctx, user_timeout ? &timeout : 0))
    {
      if (eri_live_signal_thread__sig_tmp_mask_async (sig_th, mask))
	{
	  eri_atomic_store (&th_ctx->sig_force_deliver, 0);
	  SYSCALL_RETURN_DONE (th_ctx, ERI_EAGAIN);
	}
      syscall_sig_wait (th_ctx, 0);
    }
  eri_atomic_store (&th_ctx->sig_force_deliver, 0);

  struct eri_sigframe *frame = sig_get_frame (th_ctx);
  if (frame->info.sig == ERI_LIVE_SIGNAL_THREAD_SIG_EXIT_GROUP
      || ! eri_sig_set_set (&set, frame->info.sig))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EINTR);

  struct eri_siginfo info = frame->info;
  sig_set_frame (th_ctx, 0);
  eri_live_signal_thread__sig_reset (sig_th, 0);
  if (user_info
      && ! copy_to_user (th, user_info, &info, sizeof *user_info))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EFAULT);

  SYSCALL_RETURN_DONE (th_ctx, info.sig);
}

static uint32_t
syscall_do_kill (struct eri_live_thread *th)
{
  uint32_t res = syscall_signal_thread (th);
  if (res == SYSCALL_DONE
      && eri_live_signal_thread__signaled (th->sig_th))
    syscall_sig_wait (th->ctx, 0);
  return res;
}

DEFINE_SYSCALL (kill) { return syscall_do_kill (th); }
DEFINE_SYSCALL (tkill) { return syscall_do_kill (th); }
DEFINE_SYSCALL (tgkill) { return syscall_do_kill (th); }
DEFINE_SYSCALL (rt_sigqueueinfo) { return syscall_do_kill (th); }
DEFINE_SYSCALL (rt_tgsigqueueinfo) { return syscall_do_kill (th); }

SYSCALL_TO_IMPL (restart_syscall)

SYSCALL_TO_IMPL (socket)
SYSCALL_TO_IMPL (connect)
SYSCALL_TO_IMPL (accept)
SYSCALL_TO_IMPL (accept4)
SYSCALL_TO_IMPL (sendto)
SYSCALL_TO_IMPL (recvfrom)
SYSCALL_TO_IMPL (sendmsg)
SYSCALL_TO_IMPL (sendmmsg)
SYSCALL_TO_IMPL (recvmsg)
SYSCALL_TO_IMPL (recvmmsg)
SYSCALL_TO_IMPL (shutdown)
SYSCALL_TO_IMPL (bind)
SYSCALL_TO_IMPL (listen)
SYSCALL_TO_IMPL (getsockname)
SYSCALL_TO_IMPL (getpeername)
SYSCALL_TO_IMPL (socketpair)
SYSCALL_TO_IMPL (setsockopt)
SYSCALL_TO_IMPL (getsockopt)

SYSCALL_TO_IMPL (sethostname)
SYSCALL_TO_IMPL (setdomainname)

SYSCALL_TO_IMPL (bpf)

SYSCALL_TO_IMPL (memfd_create)

SYSCALL_TO_IMPL (timerfd_create)
SYSCALL_TO_IMPL (timerfd_settime)
SYSCALL_TO_IMPL (timerfd_gettime)

SYSCALL_TO_IMPL (eventfd)
SYSCALL_TO_IMPL (eventfd2)

static uint32_t
syscall_do_signalfd (struct eri_live_thread *th)
{
  struct thread_group *group = th->group;
  struct thread_context *th_ctx = th->ctx;

  uint8_t signalfd4 = th_ctx->sregs.rax == __NR_signalfd4;
  int32_t fd = th_ctx->sregs.rdi;
  const struct eri_sigset *user_mask = (void *) th_ctx->sregs.rsi;
  uint64_t size = th_ctx->sregs.rdx;
  int32_t flags = signalfd4 ? th_ctx->sregs.r10 : 0;

  if (flags & ~(ERI_SFD_CLOEXEC | ERI_SFD_NONBLOCK))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EINVAL);

  if (size != ERI_SIG_SETSIZE) SYSCALL_RETURN_DONE (th_ctx, ERI_EINVAL);

  struct eri_sigset mask;
  if (! copy_from_user (th, &mask, user_mask, sizeof mask))
    SYSCALL_RETURN_DONE (th_ctx, ERI_EINVAL);

  if (fd == -1)
    {
      int32_t sig_fd_flags = flags & ERI_SFD_NONBLOCK;
      flags &= ~ERI_SFD_NONBLOCK;

      eri_lock (&group->sig_fd_lock);
      fd = eri_syscall (signalfd4, fd, &mask, ERI_SIG_SETSIZE, flags);
      if (! eri_syscall_is_error (fd))
	sig_fd_alloc_insert (group, fd, &mask, sig_fd_flags);
      eri_unlock (&group->sig_fd_lock);

      SYSCALL_RETURN_DONE (th_ctx, fd);
    }

  struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);
  if (! sig_fd)
    {
      uint64_t err = eri_syscall (signalfd4, fd, &mask,
				  ERI_SIG_SETSIZE, flags);
      eri_assert (err == ERI_EBADF || err == ERI_EINVAL);
      SYSCALL_RETURN_DONE (th_ctx, err);
    }

  eri_lock (&sig_fd->mask->lock);
  eri_assert_syscall (signalfd4, fd, &mask, ERI_SIG_SETSIZE, flags);
  sig_fd->mask->mask = mask;
  eri_unlock (&sig_fd->mask->lock);
  eri_unlock (&group->sig_fd_lock);
  SYSCALL_RETURN_DONE (th_ctx, fd);
}

DEFINE_SYSCALL (signalfd) { return syscall_do_signalfd (th); }
DEFINE_SYSCALL (signalfd4) { return syscall_do_signalfd (th); }

SYSCALL_TO_IMPL (pipe)
SYSCALL_TO_IMPL (pipe2)

SYSCALL_TO_IMPL (inotify_init)
SYSCALL_TO_IMPL (inotify_init1)
SYSCALL_TO_IMPL (inotify_add_watch)
SYSCALL_TO_IMPL (inotify_rm_watch)

SYSCALL_TO_IMPL (fanotify_init)
SYSCALL_TO_IMPL (fanotify_mark)

SYSCALL_TO_IMPL (userfaultfd)
SYSCALL_TO_IMPL (perf_event_open)

SYSCALL_TO_IMPL (open)
SYSCALL_TO_IMPL (openat)
SYSCALL_TO_IMPL (creat)

DEFINE_SYSCALL (close)
{
  struct thread_group *group = th->group;
  struct thread_context *th_ctx = th->ctx;
  int32_t fd = th_ctx->sregs.rdi;

  struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);
  if (! sig_fd) goto close;

  th_ctx->sregs.rax = eri_syscall (close, fd);
  if (! eri_syscall_is_error (th_ctx->sregs.rax))
    sig_fd_remove_free (group, sig_fd);
  eri_unlock (&group->sig_fd_lock);
  return SYSCALL_DONE;

close:
  SYSCALL_RETURN_DONE (th_ctx, eri_syscall (close, fd));
}

DEFINE_SYSCALL (dup)
{
  struct thread_group *group = th->group;
  struct thread_context *th_ctx = th->ctx;
  int32_t fd = th_ctx->sregs.rdi;

  struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);
  if (! sig_fd) goto dup;

  int32_t new_fd = eri_syscall (dup, fd);
  if (! eri_syscall_is_error (new_fd))
    sig_fd_copy_insert (group, new_fd, sig_fd);

  eri_unlock (&group->sig_fd_lock);
  SYSCALL_RETURN_DONE (th_ctx, new_fd);

dup:
  SYSCALL_RETURN_DONE (th_ctx, eri_syscall (dup, fd));
}

static uint32_t
syscall_do_dup2 (struct eri_live_thread *th)
{
  struct thread_group *group = th->group;
  struct thread_context *th_ctx = th->ctx;
  uint8_t dup3 = th_ctx->sregs.rax == __NR_dup3;
  int32_t fd = th_ctx->sregs.rdi;
  int32_t new_fd = th_ctx->sregs.rsi;
  int32_t flags = dup3 ? th_ctx->sregs.rdx : 0;

  if (fd == new_fd)
    SYSCALL_RETURN_DONE (th_ctx, dup3 ? ERI_EINVAL : new_fd);

  struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);
  if (! sig_fd) goto dup2;

  new_fd = eri_syscall (dup3, fd, new_fd, flags);
  if (! eri_syscall_is_error (new_fd))
    {
      struct sig_fd *new_sig_fd = sig_fd_rbt_get (group, &new_fd,
						  ERI_RBT_EQ);
      if (new_sig_fd) sig_fd_remove_free (group, new_sig_fd);

      sig_fd_copy_insert (group, new_fd, sig_fd);
    }

  eri_unlock (&group->sig_fd_lock);
  SYSCALL_RETURN_DONE (th_ctx, new_fd);

dup2:
  SYSCALL_RETURN_DONE (th_ctx, eri_syscall (dup3, fd, new_fd, flags));
}

DEFINE_SYSCALL (dup2) { return syscall_do_dup2 (th); }
DEFINE_SYSCALL (dup3) { return syscall_do_dup2 (th); }

SYSCALL_TO_IMPL (name_to_handle_at)
SYSCALL_TO_IMPL (open_by_handle_at)

DEFINE_SYSCALL (fcntl)
{
  struct thread_group *group = th->group;
  struct thread_context *th_ctx = th->ctx;
  int32_t fd = th_ctx->sregs.rdi;
  int32_t cmd = th_ctx->sregs.rsi;
  uint64_t a[] = {
    th_ctx->sregs.rdx, th_ctx->sregs.r10, th_ctx->sregs.r8, th_ctx->sregs.r9
  };

  if (cmd == ERI_F_GETFL || cmd == ERI_F_SETFL)
    {
      struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);
      if (! sig_fd) goto fcntl;

      if (cmd == ERI_F_GETFL)
	{
	  int32_t flags = eri_syscall (fcntl, fd, cmd);
	  if (! eri_syscall_is_error (flags))
	    flags |= sig_fd->flags;
	  th_ctx->sregs.rax = flags;
	}
      else
	{
	  int32_t flags = a[0];
	  int32_t sig_fd_flags = flags & ERI_O_NONBLOCK;
	  flags &= ~ERI_O_NONBLOCK;
	  th_ctx->sregs.rax = eri_syscall (fcntl, fd, cmd, flags);
	  if (! eri_syscall_is_error (th_ctx->sregs.rax))
	    sig_fd->flags = sig_fd_flags;
	}
      eri_unlock (&group->sig_fd_lock);
      return SYSCALL_DONE;
    }

fcntl:
  SYSCALL_RETURN_DONE (th_ctx, eri_syscall (fcntl, fd, cmd,
					    a[0], a[1], a[2], a[3]));
}

SYSCALL_TO_IMPL (flock)
SYSCALL_TO_IMPL (fadvise64)

SYSCALL_TO_IMPL (truncate)
SYSCALL_TO_IMPL (ftruncate)

SYSCALL_TO_IMPL (select)
SYSCALL_TO_IMPL (pselect6)
SYSCALL_TO_IMPL (poll)
SYSCALL_TO_IMPL (ppoll)

SYSCALL_TO_IMPL (epoll_create)
SYSCALL_TO_IMPL (epoll_create1)
SYSCALL_TO_IMPL (epoll_wait)
SYSCALL_TO_IMPL (epoll_pwait)
SYSCALL_TO_IMPL (epoll_ctl)

static uint32_t
syscall_do_read (struct eri_live_thread *th)
{
  struct thread_group *group = th->group;
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;
  int32_t nr = th_ctx->sregs.rax;
  int32_t fd = th_ctx->sregs.rdi;
  uint64_t a[5] = {
    th_ctx->sregs.rsi, th_ctx->sregs.rdx, th_ctx->sregs.r10,
    th_ctx->sregs.r8, th_ctx->sregs.r9
  };

  struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);
  if (! sig_fd) goto read;

  struct sig_fd_mask *mask = sig_fd->mask;
  eri_atomic_inc (&mask->ref_count);
  eri_barrier ();
  int32_t flags = sig_fd->flags;
  eri_unlock (&group->sig_fd_lock);

  struct eri_live_signal_thread__sig_fd_read_args args = {
    fd, nr, a, &mask->lock, &mask->mask, flags
  };

  uint32_t res;
  if (! eri_live_signal_thread__sig_fd_read (sig_th, &args))
    res = SYSCALL_SIG_WAIT_RESTART;
  else
    {
      if (args.result == ERI_EINTR) syscall_sig_wait (th_ctx, 0);

      th_ctx->sregs.rax = args.result;
      res = SYSCALL_DONE;
    }

  if (! eri_atomic_dec_fetch_rel (&mask->ref_count))
    eri_assert_mtfree (group->pool, mask);
  return res;

read:
  SYSCALL_RETURN_DONE (th_ctx, eri_syscall_nr (nr, fd, a[0], a[1],
					       a[2], a[3], a[4]));
}

DEFINE_SYSCALL (read) { return syscall_do_read (th); }
DEFINE_SYSCALL (pread64) { return syscall_do_read (th); }
DEFINE_SYSCALL (readv) { return syscall_do_read (th); }
DEFINE_SYSCALL (preadv) { return syscall_do_read (th); }
DEFINE_SYSCALL (preadv2) { return syscall_do_read (th); }

SYSCALL_TO_IMPL (write)
SYSCALL_TO_IMPL (pwrite64)
SYSCALL_TO_IMPL (writev)
SYSCALL_TO_IMPL (pwritev)
SYSCALL_TO_IMPL (pwritev2)

SYSCALL_TO_IMPL (fallocate)

SYSCALL_TO_IMPL (fsync)
SYSCALL_TO_IMPL (fdatasync)
SYSCALL_TO_IMPL (sync_file_range)

SYSCALL_TO_IMPL (readahead)
SYSCALL_TO_IMPL (sendfile)
SYSCALL_TO_IMPL (copy_file_range)
SYSCALL_TO_IMPL (splice)
SYSCALL_TO_IMPL (vmsplice)
SYSCALL_TO_IMPL (tee)

SYSCALL_TO_IMPL (io_setup)
SYSCALL_TO_IMPL (io_destroy)
SYSCALL_TO_IMPL (io_getevents)
SYSCALL_TO_IMPL (io_submit)
SYSCALL_TO_IMPL (io_cancel)

SYSCALL_TO_IMPL (lseek)
SYSCALL_TO_IMPL (ioctl)

SYSCALL_TO_IMPL (stat)
SYSCALL_TO_IMPL (fstat)
SYSCALL_TO_IMPL (newfstatat)
SYSCALL_TO_IMPL (lstat)
SYSCALL_TO_IMPL (access)
SYSCALL_TO_IMPL (faccessat)

SYSCALL_TO_IMPL (setxattr)
SYSCALL_TO_IMPL (fsetxattr)
SYSCALL_TO_IMPL (lsetxattr)
SYSCALL_TO_IMPL (getxattr)
SYSCALL_TO_IMPL (fgetxattr)
SYSCALL_TO_IMPL (lgetxattr)

SYSCALL_TO_IMPL (listxattr)
SYSCALL_TO_IMPL (flistxattr)
SYSCALL_TO_IMPL (llistxattr)

SYSCALL_TO_IMPL (removexattr)
SYSCALL_TO_IMPL (fremovexattr)
SYSCALL_TO_IMPL (lremovexattr)

SYSCALL_TO_IMPL (getdents)
SYSCALL_TO_IMPL (getdents64)

SYSCALL_TO_IMPL (getcwd)
SYSCALL_TO_IMPL (chdir)
SYSCALL_TO_IMPL (fchdir)
SYSCALL_TO_IMPL (rename)
SYSCALL_TO_IMPL (renameat)
SYSCALL_TO_IMPL (renameat2)
SYSCALL_TO_IMPL (mkdir)
SYSCALL_TO_IMPL (mkdirat)
SYSCALL_TO_IMPL (rmdir)

SYSCALL_TO_IMPL (link)
SYSCALL_TO_IMPL (linkat)
SYSCALL_TO_IMPL (unlink)
SYSCALL_TO_IMPL (unlinkat)
SYSCALL_TO_IMPL (symlink)
SYSCALL_TO_IMPL (symlinkat)
SYSCALL_TO_IMPL (readlink)
SYSCALL_TO_IMPL (readlinkat)

SYSCALL_TO_IMPL (mknod)
SYSCALL_TO_IMPL (mknodat)

SYSCALL_TO_IMPL (umask)

SYSCALL_TO_IMPL (chmod)
SYSCALL_TO_IMPL (fchmod)
SYSCALL_TO_IMPL (fchmodat)

SYSCALL_TO_IMPL (chown)
SYSCALL_TO_IMPL (fchown)
SYSCALL_TO_IMPL (fchownat)
SYSCALL_TO_IMPL (lchown)

SYSCALL_TO_IMPL (utime)
SYSCALL_TO_IMPL (utimes)
SYSCALL_TO_IMPL (futimesat)
SYSCALL_TO_IMPL (utimensat)

SYSCALL_TO_IMPL (ustat)
SYSCALL_TO_IMPL (statfs)
SYSCALL_TO_IMPL (fstatfs)

SYSCALL_TO_IMPL (sysfs)
SYSCALL_TO_IMPL (sync)
SYSCALL_TO_IMPL (syncfs)

SYSCALL_TO_IMPL (mount)
SYSCALL_TO_IMPL (umount2)

SYSCALL_TO_IMPL (chroot)
SYSCALL_TO_IMPL (pivot_root)

SYSCALL_TO_IMPL (mmap)
SYSCALL_TO_IMPL (mprotect)
SYSCALL_TO_IMPL (munmap)
SYSCALL_TO_IMPL (mremap)
SYSCALL_TO_IMPL (madvise)
SYSCALL_TO_IMPL (brk)

SYSCALL_TO_IMPL (msync)
SYSCALL_TO_IMPL (mincore)
SYSCALL_TO_IMPL (mlock)
SYSCALL_TO_IMPL (mlock2)
SYSCALL_TO_IMPL (mlockall)
SYSCALL_TO_IMPL (munlock)
SYSCALL_TO_IMPL (munlockall)

SYSCALL_TO_IMPL (modify_ldt)
SYSCALL_TO_IMPL (swapon)
SYSCALL_TO_IMPL (swapoff)

SYSCALL_TO_IMPL (futex)
SYSCALL_TO_IMPL (set_robust_list)
SYSCALL_TO_IMPL (get_robust_list)

SYSCALL_TO_IMPL (pkey_mprotect)
SYSCALL_TO_IMPL (pkey_alloc)
SYSCALL_TO_IMPL (pkey_free)

SYSCALL_TO_IMPL (membarrier)

SYSCALL_TO_IMPL (mbind)
SYSCALL_TO_IMPL (set_mempolicy)
SYSCALL_TO_IMPL (get_mempolicy)
SYSCALL_TO_IMPL (migrate_pages)
SYSCALL_TO_IMPL (move_pages)

SYSCALL_TO_IMPL (shmget)
SYSCALL_TO_IMPL (shmat)
SYSCALL_TO_IMPL (shmctl)
SYSCALL_TO_IMPL (shmdt)

SYSCALL_TO_IMPL (semget)
SYSCALL_TO_IMPL (semop)
SYSCALL_TO_IMPL (semtimedop)
SYSCALL_TO_IMPL (semctl)

SYSCALL_TO_IMPL (msgget)
SYSCALL_TO_IMPL (msgsnd)
SYSCALL_TO_IMPL (msgrcv)
SYSCALL_TO_IMPL (msgctl)

SYSCALL_TO_IMPL (mq_open)
SYSCALL_TO_IMPL (mq_unlink)
SYSCALL_TO_IMPL (mq_timedsend)
SYSCALL_TO_IMPL (mq_timedreceive)
SYSCALL_TO_IMPL (mq_notify)
SYSCALL_TO_IMPL (mq_getsetattr)

SYSCALL_TO_IMPL (add_key)
SYSCALL_TO_IMPL (request_key)
SYSCALL_TO_IMPL (keyctl)

SYSCALL_TO_IMPL (vhangup)

SYSCALL_TO_IMPL (reboot)
SYSCALL_TO_IMPL (kexec_load)
SYSCALL_TO_IMPL (kexec_file_load)

SYSCALL_TO_IMPL (iopl)
SYSCALL_TO_IMPL (ioperm)

SYSCALL_TO_IMPL (init_module)
SYSCALL_TO_IMPL (finit_module)
SYSCALL_TO_IMPL (delete_module)

SYSCALL_TO_IMPL (lookup_dcookie)

SYSCALL_TO_IMPL (process_vm_readv)
SYSCALL_TO_IMPL (process_vm_writev)

SYSCALL_TO_IMPL (remap_file_pages)

uint8_t
syscall (struct eri_live_thread *th)
{
  struct thread_context *th_ctx = th->ctx;

  int32_t nr = th_ctx->sregs.rax;

#define SYSCALL(name) \
  do {									\
    switch (ERI_PASTE (syscall_, name) (th))				\
      {									\
      case SYSCALL_DONE: goto done;					\
      case SYSCALL_SIG_WAIT_RESTART: goto sig_wait_restart;		\
      case SYSCALL_SEG_FAULT: goto seg_fault;				\
      default: eri_assert (0);						\
      }									\
  } while (0)

#define IF_SYSCALL(name) \
  if (nr == ERI_PASTE (__NR_, name)) SYSCALL (name);

  ERI_SYSCALLS (IF_SYSCALL)

  th_ctx->sregs.rax = ERI_ENOSYS;
  goto done;

seg_fault:
  eri_debug ("seg_fault\n");
  th_ctx->sregs.rcx = th_ctx->ext.ret;
  th_ctx->sregs.r11 = th_ctx->sregs.rflags;
  eri_atomic_store (&th_ctx->ext.op.sig_hand, SIG_HAND_NONE);
  struct eri_sigframe *sig_frame = (void *) th->stack;
  sig_frame->info.sig = ERI_SIGSEGV;
  sig_frame->info.code = ERI_SI_KERNEL;
  sig_frame->info.kill.pid = 0;
  sig_frame->info.kill.uid = 0;
  eri_assert (eri_live_thread__sig_digest_act (th, &sig_frame->info,
					       &th_ctx->sig_act));
  sig_set_frame (th_ctx, sig_frame);
  return 0;

sig_wait_restart:
  eri_debug ("sig_wait_restart\n");
  syscall_sig_wait (th_ctx, 0);
  th_ctx->ext.ret = th_ctx->ext.call;
  return 0;

done:
  eri_debug ("%u done\n", nr);
  if (nr == __NR_rt_sigreturn) return 1;
  th_ctx->sregs.rcx = th_ctx->ext.ret;
  th_ctx->sregs.r11 = th_ctx->sregs.rflags;
  return 0;
}

static void
sig_hand_syscall (struct eri_live_thread *th, struct eri_sigframe *frame,
		  struct eri_sigaction *act)
{
  struct eri_siginfo *info = &frame->info;
  struct eri_ucontext *ctx = &frame->ctx;

  if (eri_si_single_step (info)) return;

  struct thread_context *th_ctx = th->ctx;

  if (sig_access_fault (th_ctx, info, ctx)) return;

  /* XXX: SIGSYS */
  eri_assert (! eri_si_sync (info));

  sig_set (th_ctx, frame, act, SIG_HAND_NONE);
  if (th_ctx->syscall.wait_sig)
    eri_assert_syscall (futex, &th_ctx->sig_frame, ERI_FUTEX_WAKE, 1);
}

void
sync_async (struct eri_live_thread *th, uint64_t cnt)
{
  eri_atomic_store (&th->ctx->sync_async.single_step, 0);
  eri_live_thread_recorder__rec_sync_async (th->rec);
}

eri_noreturn void
sig_restart_sync_async (struct eri_live_thread *th)
{
  uint64_t cnt = sig_get_frame (th->ctx)->ctx.mctx.rcx;
  eri_live_thread_recorder__rec_restart_sync_async (th->rec, cnt);

  sig_action (th);
}

static void
sig_hand_sync_async_return_to_user (
		struct eri_live_thread *th, struct eri_sigframe *frame,
		struct eri_sigaction *act)
{
  struct eri_siginfo *info = &frame->info;
  struct eri_ucontext *ctx = &frame->ctx;

  struct thread_context *th_ctx = th->ctx;

  uint8_t intern = internal (th->group, ctx->mctx.rip);
  uint8_t inst = ctx->mctx.rip == th_ctx->ext.ret;
  uint8_t single_step = eri_si_single_step (info);

  if (intern && single_step) return;

  if (intern) eri_assert (! eri_si_sync (info));

  if (inst && single_step && ! th_ctx->sync_async.single_step)
    {
      th_ctx->sync_async.single_step = 1;
      return;
    }

  if (eri_si_sync (info) && ! sig_prepare_sync (th, info, act))
    return;

  if (intern)
    {
      ctx->mctx.rcx = th_ctx->sregs.rcx;
      ctx->mctx.rbx = th_ctx->ext.rbx;
      ctx->mctx.rip = th_ctx->ext.call;
    }

  if (inst) ctx->mctx.rip = th_ctx->ext.call;

  sig_set (th_ctx, frame, act, SIG_HAND_NONE);
  sig_return_to (th, ctx,
		 intern || inst ? sig_restart_sync_async : sig_action);
}

static void
sig_hand_sync_async (struct eri_live_thread *th, struct eri_sigframe *frame,
		     struct eri_sigaction *act)
{
  sig_hand_async (th, frame, act);
}

uint64_t
prepare_atomic (struct eri_live_thread *th,
		uint64_t access_start, uint64_t access_end)
{
  struct thread_context *th_ctx = th->ctx;
  eri_atomic_store (&th_ctx->atomic.access_start, access_start);
  eri_atomic_store (&th_ctx->atomic.access_end, access_end);

  uint64_t mem = th_ctx->ext.atomic.mem;
  uint8_t size = 1 << th_ctx->ext.op.args;
  eri_assert (size <= 16);
  struct thread_group *group = th->group;
  if (internal_range (group, mem, size)) mem = 0;
  th_ctx->atomic.idx = lock_atomic (group, mem, size);
  return mem;
}

void
complete_atomic (struct eri_live_thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  struct atomic_pair ver = unlock_atomic (th->group, &th_ctx->atomic.idx, 1);
  eri_atomic_store (&th_ctx->atomic.access_end, 0);

  struct eri_live_thread_recorder *rec = th->rec;
  uint64_t val = th_ctx->ext.atomic.val;
  switch (th_ctx->ext.op.code)
    {
    case _ERS_OP_ATOMIC_STORE:
    case _ERS_OP_ATOMIC_INC:
    case _ERS_OP_ATOMIC_DEC:
      eri_live_thread_recorder__rec_atomic (rec, &ver.first);
      break;
    case _ERS_OP_ATOMIC_LOAD:
    case _ERS_OP_ATOMIC_XCHG:
    case _ERS_OP_ATOMIC_CMPXCHG:
      eri_live_thread_recorder__rec_atomic_load (rec, &ver.first, val);
      break;
    default: eri_assert (0);
    }
}

static eri_noreturn void sig_restart_atomic (struct eri_live_thread *th);

static eri_noreturn void
sig_restart_atomic (struct eri_live_thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  unlock_atomic (th->group, &th_ctx->atomic.idx, 0);

  th_ctx->atomic.access_end = 0;
  sig_restart_set_ctx (th_ctx);

  sig_action (th);
}

static void
sig_hand_atomic (struct eri_live_thread *th, struct eri_sigframe *frame,
		 struct eri_sigaction *act)
{
  struct eri_siginfo *info = &frame->info;
  struct eri_ucontext *ctx = &frame->ctx;

  if (eri_si_single_step (info)) return;

  struct thread_context *th_ctx = th->ctx;
  if (eri_si_sync (info))
      eri_assert ((info->sig == ERI_SIGSEGV || info->sig == ERI_SIGBUS)
		  && ctx->mctx.rip >= th_ctx->atomic.access_start
		  && ctx->mctx.rip < th_ctx->atomic.access_end);

  if (eri_si_sync (info))
    {
      if (sig_get_frame (th_ctx))
	{
	  struct eri_ucontext *sig_ctx = &sig_get_frame (th_ctx)->ctx;
	  sig_ctx->mctx.rbp = ctx->mctx.rbp;
	  sig_ctx->mctx.r12 = ctx->mctx.r12;
	  sig_ctx->mctx.r13 = ctx->mctx.r13;
	  sig_ctx->mctx.r14 = ctx->mctx.r14;
	  sig_ctx->mctx.r15 = ctx->mctx.r15;
	  sig_return_to (th, ctx, sig_restart_atomic);
	}
      else
	{
	  eri_assert (sig_prepare_sync (th, info, act));

	  sig_set (th_ctx, frame, act, SIG_HAND_NONE);
	  sig_return_to (th, ctx, sig_restart_atomic);
	}
      return;
    }

  /* This sig_hand should be able to handle early signals in sig_action.  */
  sig_set (th_ctx, frame, act, SIG_HAND_ATOMIC);
}

void
eri_live_thread__sig_handler (
		struct eri_live_thread *th, struct eri_sigframe *frame,
		struct eri_sigaction *act)
{
  struct eri_siginfo *info = &frame->info;
  eri_debug ("sig_hand = %u, sig = %u, rip = %lx\n",
	     th->ctx->ext.op.sig_hand, info->sig, frame->ctx.mctx.rip);

  const void (*hands[]) (
	    struct eri_live_thread *, struct eri_sigframe *,
	    struct eri_sigaction *) = {
#define SIG_HAND_ARRAY_ELT(chand, hand)	hand,
    SIG_HANDS (SIG_HAND_ARRAY_ELT)
  };

  struct eri_sigaction sync_act;
  if (eri_si_sync (info)) act = &sync_act;
  hands[th->ctx->ext.op.sig_hand] (th, frame, act);
}

int32_t
eri_live_thread__get_pid (const struct eri_live_thread *th)
{
  return th->group->pid;
}

int32_t
eri_live_thread__get_tid (const struct eri_live_thread *th)
{
  return th->tid;
}
