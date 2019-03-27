#include <stdarg.h>

#include <common.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/elf.h>
#include <lib/lock.h>
#include <lib/rbtree.h>
#include <lib/malloc.h>
#include <lib/syscall.h>
#include <lib/atomic.h>

#include <public/common.h>

#include <live/rtld.h>
#include <live/signal-thread.h>
#include <live/thread-recorder.h>
#include <live/thread.h>
#include <live/thread-local.h>

#define THREAD_SIG_STACK_SIZE	(2 * 4096)

#define th_ctx_sregs(th_ctx)	eri_th_ctx_sregs (th_ctx)

#define SET_CTX_SREG_FROM_TH_CTX(creg, reg, c, t) \
  (c)->mctx.reg = th_ctx_sregs (t)->reg;

#define set_ctx_sregs_from_th_ctx(ctx, th_ctx) \
  do {									\
    struct eri_ucontext *_ctx = ctx;					\
    struct thread_context *_th_ctx = th_ctx;				\
    ERI_ENTRY_FOREACH_SREG (SET_CTX_SREG_FROM_TH_CTX, _ctx, _th_ctx)	\
  } while (0)

#define SET_TH_CTX_SREG_FROM_CTX(creg, reg, th, c) \
  (th)->ctx.sregs.reg = (c)->mctx.reg;

#define set_th_ctx_sregs_from_ctx(th_ctx, ctx) \
  do {									\
    struct thread_context *_th_ctx = th_ctx;				\
    struct eri_ucontext *_ctx = ctx;					\
    ERI_ENTRY_FOREACH_SREG (SET_TH_CTX_SREG_FROM_CTX, _th_ctx, _ctx)	\
  } while (0)

struct eri_live_thread_group;

struct eri_live_thread
{
  struct eri_live_thread_group *group;
  struct eri_live_signal_thread *sig_th;
  uint64_t id;
  int32_t alive;
  struct eri_lock start_lock;
  int32_t *clear_user_tid;

  struct eri_live_thread_recorder *rec;

  struct thread_context *ctx;

  int32_t tid;

  struct eri_stack sig_alt_stack;

  eri_aligned16 uint8_t sig_stack[2 * THREAD_SIG_STACK_SIZE];

  eri_aligned16 uint8_t stack[0];
};

#define th_sregs(th)		th_ctx_sregs ((th)->ctx)

struct sig_fd_mask
{
  uint64_t ref_count;
  struct eri_lock lock;
  struct eri_sigset mask;
};

struct sig_fd
{
  int32_t fd;
  struct sig_fd_mask *mask;
  int32_t flags;

  ERI_RBT_NODE_FIELDS (sig_fd, struct sig_fd)
};

struct eri_live_thread_group
{
  struct eri_mtpool *pool;

  uint64_t map_start;
  uint64_t map_end;

  int32_t pid;

  struct eri_lock sig_fd_lock;
  ERI_RBT_TREE_FIELDS (sig_fd, struct sig_fd)

  uint64_t *atomic_table;
  uint64_t atomic_table_size;

  uint64_t th_id;
  uint64_t stack_size;

  const char *path;
  uint64_t file_buf_size;

  uint64_t io;
};

ERI_DEFINE_RBTREE (static, sig_fd, struct eri_live_thread_group,
		   struct sig_fd, int32_t, eri_less_than)

static struct sig_fd *
sig_fd_alloc_insert (struct eri_live_thread_group *group, int32_t fd,
		     const struct eri_sigset *mask, int32_t flags)
{
  struct sig_fd *sig_fd = eri_assert_mtmalloc (group->pool, sizeof *sig_fd);
  sig_fd->fd = fd;
  sig_fd->mask = eri_assert_mtmalloc (group->pool, sizeof *sig_fd->mask);
  sig_fd->mask->ref_count = 1;
  eri_init_lock (&sig_fd->mask->lock, 0);
  sig_fd->mask->mask = *mask;
  sig_fd->flags = flags;
  sig_fd_rbt_insert (group, sig_fd);
  return sig_fd;
}

static struct sig_fd *
sig_fd_copy_insert (struct eri_live_thread_group *group, int32_t fd,
		    const struct sig_fd *sig_fd)
{
  return sig_fd_alloc_insert (group, fd, &sig_fd->mask->mask, sig_fd->flags);
}

static void
sig_fd_remove_free (struct eri_live_thread_group *group, struct sig_fd *fd)
{
  sig_fd_rbt_remove (group, fd);
  if (! eri_atomic_dec_fetch_rel (&fd->mask->ref_count))
    eri_assert_mtfree (group->pool, fd->mask);
  eri_assert_mtfree (group->pool, fd);
}

static struct sig_fd *
sig_fd_try_lock (struct eri_live_thread_group *group, int32_t fd)
{
  eri_assert_lock (&group->sig_fd_lock);
  struct sig_fd *sig_fd = sig_fd_rbt_get (group, &fd, ERI_RBT_EQ);
  if (! sig_fd) eri_assert_unlock (&group->sig_fd_lock);
  return sig_fd;
}

ERI_DEFINE_THREAD_UTILS (struct eri_live_thread, struct eri_live_thread_group)

static void
disable_vdso (struct eri_auxv *auxv)
{
  for (; auxv->type != ERI_AT_NULL; ++auxv)
    if (auxv->type == ERI_AT_SYSINFO || auxv->type == ERI_AT_SYSINFO_EHDR)
      auxv->type = ERI_AT_IGNORE;
}

static uint64_t
io_in (struct eri_live_thread *th)
{
  return eri_atomic_load (&th->group->io);
}

static uint64_t
io_out (struct eri_live_thread *th)
{
  return eri_atomic_fetch_inc (&th->group->io);
}

struct eri_live_thread_group *
eri_live_thread__create_group (struct eri_mtpool *pool,
			       struct eri_live_rtld_args *rtld_args)
{
  uint64_t atomic_table_size =  2 * 1024 * 1024;

  uint64_t stack_size = 2 * 1024 * 1024;
  const char *path = "ers-data";
  uint64_t file_buf_size = 64 * 1024;

  if (rtld_args->envp)
    {
      char **p;
      for (p = rtld_args->envp; *p; ++p)
	(void) (eri_get_arg_int (*p, "ERS_ATOMIC_TABLE_SIZE=",
				 &atomic_table_size, 10)
	|| eri_get_arg_int (*p, "ERS_STACK_SIZE=", &stack_size, 10)
	|| eri_get_arg_str (*p, "ERS_DATA=", (void *) &path)
	|| eri_get_arg_int (*p, "ERS_FILE_BUF_SIZE=", &file_buf_size, 10));
    }

  struct eri_live_thread_group *group
			= eri_assert_mtmalloc (pool, sizeof *group);
  group->pool = pool;
  group->map_start = rtld_args->map_start;
  group->map_end = rtld_args->map_end;
  group->pid = 0;

  eri_init_lock (&group->sig_fd_lock, 0);
  ERI_RBT_INIT_TREE (sig_fd, group);

  group->atomic_table = eri_assert_mtmalloc (pool,
		atomic_table_size * sizeof *group->atomic_table);
  group->atomic_table_size = atomic_table_size;

  group->th_id = 0;
  group->stack_size = stack_size;
  group->path = path;
  group->file_buf_size = file_buf_size;

  group->io = 0;
  return group;
}

void
eri_live_thread__destroy_group (struct eri_live_thread_group *group)
{
  struct sig_fd *fd, *nfd;
  ERI_RBT_FOREACH_SAFE (sig_fd, group, fd, nfd)
    sig_fd_remove_free (group, fd);

  eri_assert_mtfree (group->pool, group->atomic_table);
  eri_assert_mtfree (group->pool, group);
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

static void
swallow_single_step (struct thread_context *th_ctx)
{
  if (th_ctx_sregs (th_ctx)->rflags & ERI_RFLAGS_TRACE_MASK)
    eri_atomic_store (&th_ctx->swallow_single_step, 1);
}

static struct thread_context *
create_context (struct eri_mtpool *pool, struct eri_live_thread *th)
{
  struct thread_context *th_ctx = eri_assert_mtmalloc (pool,
	sizeof *th_ctx + eri_entry_thread_entry_text_size (thread_context));

  eri_entry_init (&th_ctx->ext, &th_ctx->ctx, thread_context, th_ctx->text,
		  entry, th->stack + th->group->stack_size);

  th_ctx->sig_force_deliver = 0;
  sig_set_frame (th_ctx, 0);
  th_ctx->access = 0;
  th_ctx->swallow_single_step = 0;
  th_ctx->syscall.wait_sig = 0;
  th_ctx->syscall.sig_intr = 0;
  th_ctx->atomic.access_end = 0;
  th_ctx->th = th;
  return th_ctx;
}

static struct eri_live_thread *
create (struct eri_live_thread_group *group,
	struct eri_live_signal_thread *sig_th, int32_t *clear_user_tid)
{
  struct eri_live_thread *th
	= eri_assert_mtmalloc (group->pool, sizeof *th + group->stack_size);
  th->group = group;
  eri_debug ("%lx %lx\n", th, sig_th);
  th->sig_th = sig_th;
  th->id = eri_atomic_fetch_inc (&group->th_id);
  th->alive = 1;
  eri_init_lock (&th->start_lock, 1);
  th->clear_user_tid = clear_user_tid;
  th->rec = eri_live_thread_recorder__create (
		group->pool, group->path, th->id, group->file_buf_size);

  th->ctx = create_context (group->pool, th);
  return th;
}

struct eri_live_thread *
eri_live_thread__create_main (struct eri_live_thread_group *group,
			      struct eri_live_signal_thread *sig_th,
			      struct eri_live_rtld_args *rtld_args)
{
  if (rtld_args->auxv) disable_vdso (rtld_args->auxv);

  struct eri_live_thread *th = create (group, sig_th, 0);
  th->alive = 1;
  eri_init_lock (&th->start_lock, 1);
  struct thread_context *th_ctx = th->ctx;
  th_ctx->ext.op.sig_hand = SIG_HAND_ASYNC;
  th_ctx->ext.op.args = 0;
  th_ctx->ext.op.code = _ERS_OP_SYSCALL;
  th_ctx->ext.rbx = 0;
  th_ctx->ext.ret = rtld_args->rip;
  th_ctx->ctx.rsp = rtld_args->rsp;
#define ZERO_REG(creg, reg, regs)	(regs)->reg = 0;
  ERI_ENTRY_FOREACH_SREG (ZERO_REG, th_sregs (th))
  th_sregs (th)->rdx = rtld_args->rdx;
  ERI_ENTRY_FOREACH_EREG (ZERO_REG, &th_ctx->syscall.eregs)
  eri_assert_syscall (sigaltstack, 0, &th->sig_alt_stack);
  return th;
}

static struct thread_context *
start (struct eri_live_thread *th)
{
  eri_debug ("%lx %lx %lx %lx\n",
	     th, th->ctx, th->ctx->sig_frame, th->ctx->ctx.top);
  eri_assert_syscall (prctl, ERI_PR_SET_PDEATHSIG, ERI_SIGKILL);
  eri_assert (eri_assert_syscall (getppid)
	      == eri_live_signal_thread__get_pid (th->sig_th));

  eri_live_signal_thread__init_thread_sig_stack (
	th->sig_th, th->sig_stack, 2 * THREAD_SIG_STACK_SIZE);

  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_GS, th->ctx);

  eri_assert_lock (&th->start_lock);
  eri_debug ("leave %lx %lx\n",
	     __builtin_return_address (0), th->ctx->sig_frame);

  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);
  return th->ctx;
}

void
start_main (struct eri_live_thread *th)
{
  /* XXX: unspecified? necessary? */
  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_FS, 0);

  struct eri_live_thread_group *group = th->group;
  struct thread_context *th_ctx = th->ctx;
  struct eri_init_record rec = {
    0, th_sregs (th)->rdx, th_ctx->ctx.rsp, th_ctx->ext.ret,
    *eri_live_signal_thread__get_sig_mask (th->sig_th), th->sig_alt_stack,
    eri_live_signal_thread__get_pid (th->sig_th),
    group->map_start, group->map_end, group->atomic_table_size
  };
  eri_live_thread_recorder__rec_init (th->rec, &rec);
  start (th);
}

void
eri_live_thread__clone_main (struct eri_live_thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  struct eri_sys_clone_args args = {

    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID
    | ERI_SIGCHLD,

    (void *) th_ctx->ctx.top, &th->tid, &th->alive, 0, main, th_ctx
  };

  th->group->pid = eri_assert_sys_clone (&args);
  eri_assert_unlock (&th->start_lock);
}

static void
sig_digest_act (const struct eri_siginfo *info, struct eri_sigaction *act)
{
  int32_t sig = info->sig;

  if (eri_si_sync (info) && act->act == ERI_SIG_IGN) act->act = ERI_SIG_DFL;

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
	act->act = ERI_SIG_ACT_TERM;
      else if (sig == ERI_SIGQUIT || sig == ERI_SIGILL || sig == ERI_SIGABRT
	       || sig == ERI_SIGFPE || sig == ERI_SIGSEGV || sig == ERI_SIGBUS
	       || sig == ERI_SIGSYS || sig == ERI_SIGTRAP
	       || sig == ERI_SIGXCPU || sig == ERI_SIGXFSZ)
	act->act = ERI_SIG_ACT_CORE;
      else if (sig == ERI_SIGTSTP || sig == ERI_SIGTTIN || sig == ERI_SIGTTOU)
	act->act = ERI_SIG_ACT_STOP;
      else eri_assert_unreachable ();
    }
}

uint8_t
eri_live_thread__sig_digest_act (
		struct eri_live_thread *th, const struct eri_siginfo *info,
		struct eri_ver_sigaction *act)
{
  /*
   * Though this function can be called in different async contexts,
   * This can only happen synchronizly regards to the sig_mask.
   */
  if (eri_si_sync (info) && eri_sig_set_set (
	eri_live_signal_thread__get_sig_mask (th->sig_th), info->sig))
    act->act.act = ERI_SIG_DFL;

  sig_digest_act (info, &act->act);

  struct eri_sigset *force = th->ctx->sig_force_deliver;
  return act->act.act || (force && eri_sig_set_set (force, info->sig));
}

static uint8_t
sig_setup_user_frame (struct eri_live_thread *th, struct eri_sigframe *frame)
{
  eri_debug ("\n");

  uint64_t top = (uint64_t) th->sig_stack + 2 * THREAD_SIG_STACK_SIZE;
  eri_assert ((uint64_t) frame >= top - THREAD_SIG_STACK_SIZE
	      && (uint64_t) frame < top);

  struct thread_context *th_ctx = th->ctx;

  struct eri_sigframe *user_frame = eri_sig_setup_user_frame (
		frame, &th_ctx->sig_act.act, &th->sig_alt_stack,
		eri_live_signal_thread__get_sig_mask (th->sig_th),
		copy_to_user, th);

  if (! user_frame) return 0;

  th_ctx->sig_act_frame = user_frame;
  eri_debug ("leave\n");
  return 1;
}

static void
record_signal (struct eri_live_thread *th,
	       struct eri_siginfo *info, struct eri_ver_sigaction *act)
{
  if (info && eri_si_sync (info))
    {
      eri_live_thread_recorder__rec_signal (th->rec, 0, act);
      return;
    }

  struct eri_signal_record rec = { io_in (th) };
  if (info) {  rec.info = *info; rec.act = *act; }
  eri_live_thread_recorder__rec_signal (th->rec, 1, &rec);
}

static eri_noreturn void
die (struct eri_live_thread *th)
{
  record_signal (th, 0, 0);
  eri_live_signal_thread__die (th->sig_th);
  eri_assert_sys_thread_die (&th->alive);
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
  struct eri_siginfo *info = &frame->info;

  /* XXX: core, die context */
  if (info->sig == ERI_LIVE_SIGNAL_THREAD_SIG_EXIT_GROUP) die (th);

  eri_atomic_store (&th_ctx->ext.op.sig_hand, SIG_HAND_SIG_ACTION);

  struct eri_sigaction *act = &th_ctx->sig_act.act;

  eri_assert (act->act);
  if (! eri_sig_act_internal_act (act->act))
    {
      /* XXX: swallow? */
      th_ctx->swallow_single_step = 0;

      if (! sig_setup_user_frame (th, frame)) goto core;

      record_signal (th, info, &th_ctx->sig_act);

      struct eri_stack st = {
	(uint64_t) th->sig_stack, ERI_SS_AUTODISARM, 2 * THREAD_SIG_STACK_SIZE
      };
      eri_assert_syscall (sigaltstack, &st, 0);

      eri_live_signal_thread__sig_reset (sig_th, &act->mask);
      eri_sig_act (th_ctx->sig_act_frame, act->act);
    }

  if (act->act == ERI_SIG_ACT_STOP)
    {
      /* TODO: stop */

      struct eri_sigframe *act_frame = (void *) th->stack;
      act_frame->ctx.mctx = frame->ctx.mctx;
      act_frame->restorer = eri_assert_sys_sigreturn;
      th_ctx->sig_act_frame = act_frame;
      eri_live_signal_thread__sig_reset (sig_th, 0);
      sig_return (frame);
    }

  if (act->act == ERI_SIG_ACT_TERM) core_status = 130;

  struct eri_sigset mask;
core:
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);
  eri_live_signal_thread__sig_reset (sig_th, &mask);
  eri_debug ("core\n");
  if (eri_live_signal_thread__exit (sig_th, 1, core_status))
    {
      record_signal (th, info, &th_ctx->sig_act);

      if (core_status == 130) eri_assert_syscall (exit, 0);
      eri_assert_unreachable ();
    }
  else die (th);
}

static void
sig_set (struct thread_context *th_ctx, struct eri_sigframe *frame,
	 const struct eri_ver_sigaction *act, uint8_t sig_hand)
{
  sig_set_frame (th_ctx, frame);
  th_ctx->sig_act = *act;

  th_ctx->ext.op.sig_hand = sig_hand;
  eri_assert (frame->ctx.stack.flags == ERI_SS_AUTODISARM);
  frame->ctx.stack.size -= THREAD_SIG_STACK_SIZE;
}

static void
sig_return_to (struct eri_live_thread *th,
	       struct eri_ucontext *ctx, void *fn)
{
  struct thread_context *th_ctx = th->ctx;
  uint64_t *stack = (void *) th_ctx->ctx.top;
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
sig_prepare_sync (struct eri_live_thread *th, struct eri_siginfo *info,
		  struct eri_ver_sigaction *act)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  eri_live_signal_thread__sig_prepare_sync (sig_th, info, act);

  if (! eri_si_sync (info)) return 1;

  return eri_live_thread__sig_digest_act (th, info, act);
}

static void
sig_hand_async (struct eri_live_thread *th, struct eri_sigframe *frame,
		struct eri_ver_sigaction *act)
{
  eri_debug ("\n");

  struct eri_siginfo *info = &frame->info;

  if (eri_si_single_step (info)) return;
  eri_assert (! eri_si_sync (info));

  sig_set (th->ctx, frame, act, SIG_HAND_NONE);
}

static void
sig_hand_none (struct eri_live_thread *th, struct eri_sigframe *frame,
	       struct eri_ver_sigaction *act)
{
  eri_assert (eri_si_single_step (&frame->info));
}

static void
sig_hand_sig_action (struct eri_live_thread *th, struct eri_sigframe *frame,
		     struct eri_ver_sigaction *act)
{
  struct thread_context *th_ctx = th->ctx;

  struct eri_siginfo *info = &frame->info;
  struct eri_ucontext *ctx = &frame->ctx;

  if (internal (th->group, ctx->mctx.rip))
    {
      if (sig_access_fault (th_ctx, info, ctx)) return;
      if (eri_si_single_step (info)) return;
      eri_assert (! eri_si_sync (info));

      if (th_ctx->sig_act.act.act == ERI_SIG_ACT_STOP)
	ctx->mctx = th_ctx->sig_act_frame->ctx.mctx;
      else
	{
	  ctx->mctx.rip = (uint64_t) th_ctx->sig_act.act.act;
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
		struct eri_ver_sigaction *act)
{
  struct eri_siginfo *info = &frame->info;
  struct eri_ucontext *ctx = &frame->ctx;

  uint8_t intern = internal (th->group, ctx->mctx.rip);
  uint8_t single_step = eri_si_single_step (info);

  struct thread_context *th_ctx = th->ctx;

  if (intern && single_step) return;

  if (single_step && th_ctx->swallow_single_step)
    {
      th_ctx->swallow_single_step = 0;
      return;
    }

  if (intern) eri_assert (! eri_si_sync (info));

  if (eri_si_sync (info) && ! sig_prepare_sync (th, info, act))
    return;

  if (intern)
    {
      ctx->mctx.rcx = th_ctx_sregs (th_ctx)->rcx;
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

  ctx->mctx.rsp = th_ctx->ctx.rsp;
  set_ctx_sregs_from_th_ctx (ctx, th_ctx);
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

  int32_t flags = th_sregs (pth)->rdi;
  int32_t *ctid = (void *) th_sregs (pth)->r10;
  int32_t *clear_user_tid = flags & ERI_CLONE_CHILD_CLEARTID ? ctid : 0;
  struct eri_live_thread *th = create (pth->group, sig_th, clear_user_tid);

  create_args->cth = th;
  struct thread_context *th_ctx = th->ctx;
  th_ctx->ext.op = pth_ctx->ext.op;
  th_ctx->ext.rbx = pth_ctx->ext.rbx;
  th_ctx->ext.ret = pth_ctx->ext.ret;
  th_ctx->ctx.rsp = th_sregs (pth)->rsi;
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  *sregs = *th_sregs (pth);
  sregs->rax = 0;
  sregs->rcx = th_ctx->ext.ret;
  sregs->r11 = sregs->rflags;
  th_ctx->syscall.eregs = pth_ctx->syscall.eregs;
  *(uint64_t *) (th_ctx->ctx.top - 8) = *(uint64_t *) (pth_ctx->ctx.top - 8);
  eri_debug ("%lx %lx\n",
	     th_ctx->ctx.top, *(uint64_t *) (th_ctx->ctx.top - 8));
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
  void *new_tls = (void *) th_sregs (th)->r8;
  struct eri_sys_clone_args args = {

    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_THREAD
    | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID
    | (new_tls ? ERI_CLONE_SETTLS : 0),

    (void *) (th_ctx->ctx.top - 8),
    &th->tid, &th->alive, new_tls, start, th
  };

  eri_debug ("clone %lx\n", args.stack);
  uint64_t res = eri_sys_clone (&args);

  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  return res;
}

static void
destroy_context (struct eri_mtpool *pool, struct thread_context *ctx)
{
  eri_assert_mtfree (pool, ctx);
}

void
eri_live_thread__destroy (struct eri_live_thread *th)
{
  struct eri_live_thread_group *group = th->group;
  struct eri_mtpool *pool = group->pool;

  destroy_context (pool, th->ctx);
  eri_live_thread_recorder__destroy (th->rec);
  eri_assert_mtfree (pool, th);
}

void
eri_live_thread__join (struct eri_live_thread *th)
{
  eri_assert_sys_futex_wait (&th->alive, 1, 0);
}

static uint64_t
do_lock_atomic (struct eri_live_thread_group *group, uint64_t slot)
{
  uint64_t idx = eri_atomic_hash (slot, group->atomic_table_size);

  uint32_t i = 0;
  while (eri_atomic_bit_test_set (group->atomic_table + idx, 0))
    if (++i % 16 == 0) eri_assert_syscall (sched_yield);
  eri_barrier ();
  return idx;
}

static struct atomic_pair
lock_atomic (struct eri_live_thread_group *group, uint64_t mem, uint8_t size)
{
  struct atomic_pair idx = { do_lock_atomic (group, eri_atomic_slot (mem)) };
  idx.second = eri_atomic_cross_slot (mem, size)
	? do_lock_atomic (group, eri_atomic_slot2 (mem, size)) : idx.first;
  return idx;
}

static void
do_unlock_atomic (struct eri_live_thread_group *group, uint64_t idx)
{
  eri_barrier ();
  eri_atomic_and (group->atomic_table + idx, -2);
}

static struct atomic_pair
unlock_atomic (struct eri_live_thread_group *group, struct atomic_pair *idx,
	       uint8_t update)
{
  uint8_t cross = idx->first != idx->second;
  struct atomic_pair ver = {
    group->atomic_table[idx->first] >> 1,
    group->atomic_table[idx->second] >> 1
  };


  if (update)
    {
      group->atomic_table[idx->first] += 2;
      if (cross) group->atomic_table[idx->second] += 2;
    }

  do_unlock_atomic (group, idx->first);
  if (cross) do_unlock_atomic (group, idx->second);
  return ver;
}

#define SYSCALL_DONE			0
#define SYSCALL_SIG_WAIT_RESTART	1
#define SYSCALL_SEG_FAULT		2

#define SYSCALL_RETURN_DONE(sregs, result) \
  do {									\
    (sregs)->rax = result;						\
    return SYSCALL_DONE;						\
  } while (0)

#define DEFINE_SYSCALL(name) \
static uint32_t								\
ERI_PASTE (syscall_, name) (struct eri_live_thread *th)

#define SYSCALL_TO_IMPL(name) \
DEFINE_SYSCALL (name) { SYSCALL_RETURN_DONE (th_sregs (th), ERI_ENOSYS); }

static void
syscall_record (struct eri_live_thread *th, uint16_t magic, void *rec)
{
  eri_live_thread_recorder__rec_syscall (th->rec, magic, rec);
}

static void
syscall_record_in (struct eri_live_thread *th)
{
  syscall_record (th, ERI_SYSCALL_IN_MAGIC, (void *) io_in (th));
}

static void
syscall_record_res_in (struct eri_live_thread *th)
{
  uint64_t rec[2] = { th_sregs (th)->rax, io_in (th) };
  syscall_record (th, ERI_SYSCALL_RESULT_IN_MAGIC, rec);
}

static void
syscall_record_out (struct eri_live_thread *th)
{
  syscall_record (th, ERI_SYSCALL_OUT_MAGIC, (void *) io_out (th));
}

static void
syscall_record_kill (struct eri_live_thread *th,
		     struct eri_syscall_kill_record *rec)
{
  rec->in = io_in (th);
  syscall_record (th, ERI_SYSCALL_KILL_MAGIC, rec);
}

static void
syscall_syscall (struct thread_context *th_ctx)
{
  struct eri_sys_syscall_args args;
  eri_sys_syscall_args_from_sregs (&args, th_ctx_sregs (th_ctx));
  th_ctx_sregs (th_ctx)->rax = eri_sys_syscall (&args);
};

static void
syscall_signal_thread (struct eri_live_thread *th)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct eri_sys_syscall_args args;
  eri_sys_syscall_args_from_sregs (&args, th_sregs (th));
  th_sregs (th)->rax = eri_live_signal_thread__syscall (sig_th, &args);
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
  struct eri_entry_scratch_registers *sregs = th_sregs (th);

  int32_t flags = sregs->rdi;
  int32_t *user_ptid = (void *) sregs->rdx;
  int32_t *user_ctid = (void *) sregs->r10;
  /* XXX: support more */
  eri_assert (flags == ERI_CLONE_SUPPORTED_FLAGS);

  struct eri_live_thread__create_args create_args = { th };
  struct eri_live_signal_thread__clone_args args = { &create_args };

  if (! eri_live_signal_thread__clone (sig_th, &args))
    return SYSCALL_SIG_WAIT_RESTART;

  struct eri_syscall_clone_record rec = {
    args.out, args.result, create_args.cth->id
  };

  if (! eri_syscall_is_error (args.result))
    {
      if (flags & ERI_CLONE_PARENT_SETTID)
	copy_to_user (th, user_ptid, &args.result, sizeof *user_ptid);
      if (flags & ERI_CLONE_CHILD_SETTID)
	copy_to_user (th, user_ctid, &args.result, sizeof *user_ctid);
      rec.id = create_args.cth->id;
      eri_assert_unlock (&create_args.cth->start_lock);
    }
  syscall_record (th, ERI_SYSCALL_CLONE_MAGIC, &rec); 
  SYSCALL_RETURN_DONE (sregs, args.result);
}

SYSCALL_TO_IMPL (unshare)
SYSCALL_TO_IMPL (kcmp)
SYSCALL_TO_IMPL (fork)
SYSCALL_TO_IMPL (vfork)
SYSCALL_TO_IMPL (setns)

DEFINE_SYSCALL (set_tid_address)
{
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  th->clear_user_tid = (void *) sregs->rdi;
  SYSCALL_RETURN_DONE (sregs, 0);
}

static uint8_t
clear_user_tid (struct thread_context *th_ctx,
		int32_t *user_tid, int32_t *old_val)
{
  uint8_t fault = 0;
  *old_val = 0;

  extern uint8_t clear_user_tid_access[];
  extern uint8_t clear_user_tid_access_fault[];
  eri_atomic_store (&th_ctx->access, (uint64_t) clear_user_tid_access);
  th_ctx->access_fault = (uint64_t) clear_user_tid_access_fault;

  asm ("clear_user_tid_access:\n"
       "  xchgl\t%0, %1\n"
       "  jmp\t1f\n"
       "clear_user_tid_access_fault:\n"
       "  movb\t$1, %b2\n"
       "1:" : "+r" (*old_val), "=m" (*user_tid), "+r" (fault) : : "memory");

  eri_atomic_store (&th_ctx->access, 0);
  return ! fault;
}

static uint32_t
syscall_do_exit (struct eri_live_thread *th)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;
  int32_t nr = th_sregs (th)->rax;
  uint8_t exit_group = nr == __NR_exit_group;
  int32_t status = th_sregs (th)->rdi;

  if (! eri_live_signal_thread__exit (sig_th, exit_group, status))
    return SYSCALL_SIG_WAIT_RESTART;

  if (th->clear_user_tid) /* XXX: die? replay as well */
    {
      struct eri_live_thread_group *group = th->group;

      int32_t *user_tid = th->clear_user_tid;
      struct atomic_pair idx
	= lock_atomic (group, (uint64_t) user_tid, sizeof *user_tid);

      int32_t old_val;
      if (clear_user_tid (th_ctx, user_tid, &old_val))
	{
	  uint8_t update = old_val != 0;
	  struct atomic_pair ver = unlock_atomic (group, &idx, update);
	  eri_live_thread_recorder__rec_atomic (th->rec, update,
						&ver.first, 0);
	  eri_syscall (futex, user_tid, ERI_FUTEX_WAKE, 1);
	}
      else unlock_atomic (group, &idx, 0);
    }

  syscall_record_out (th);

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
  SYSCALL_RETURN_DONE (th_sregs (th),
		       eri_live_signal_thread__get_tid (th->sig_th));
}

DEFINE_SYSCALL (getpid)
{
  SYSCALL_RETURN_DONE (th_sregs (th),
		       eri_live_signal_thread__get_pid (th->sig_th));
}

DEFINE_SYSCALL (getppid)
{
  syscall_signal_thread (th);
  syscall_record_res_in (th);
  return SYSCALL_DONE;
}

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
  eri_common_syscall_arch_prctl (th_sregs (th), copy_to_user, th);
  return SYSCALL_DONE;
}

SYSCALL_TO_IMPL (quotactl)
SYSCALL_TO_IMPL (acct)

SYSCALL_TO_IMPL (setpriority)
SYSCALL_TO_IMPL (getpriority)

DEFINE_SYSCALL (sched_yield)
{
  syscall_syscall (th->ctx);
  return SYSCALL_DONE;
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
  struct eri_entry_scratch_registers *sregs = th_sregs (th);

  struct eri_sigset old_mask;
  old_mask = *eri_live_signal_thread__get_sig_mask (sig_th);

  struct eri_sigset mask;
  if (! eri_common_syscall_rt_sigprocmask_get (
			sregs, &old_mask, &mask, copy_from_user, th))
    return SYSCALL_DONE;

  if (sregs->rsi)
    {
      if (! eri_live_signal_thread__sig_mask_async (sig_th, &mask))
	return SYSCALL_SIG_WAIT_RESTART;

      if (eri_live_signal_thread__signaled (sig_th))
	syscall_sig_wait (th->ctx, 0);
    }

  eri_common_syscall_rt_sigprocmask_set (
			sregs, &old_mask, copy_to_user, th);
  return SYSCALL_DONE;
}

DEFINE_SYSCALL (rt_sigaction)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct eri_entry_scratch_registers *sregs = th_sregs (th);

  int32_t sig = sregs->rdi;
  const struct eri_sigaction *user_act = (void *) sregs->rsi;
  struct eri_sigaction *user_old_act = (void *) sregs->rdx;

  if (! eri_sig_catchable (sig)) SYSCALL_RETURN_DONE (sregs, ERI_EINVAL);

  if (! user_act && ! user_old_act) SYSCALL_RETURN_DONE (sregs, 0);

  struct eri_sigaction act;
  if (user_act && ! copy_from_user (th, &act, user_act, sizeof act))
    SYSCALL_RETURN_DONE (sregs, ERI_EFAULT);

  struct eri_ver_sigaction old_act;
  struct eri_live_signal_thread__sig_action_args args = {
    sig, user_act ? &act : 0, user_old_act ? &old_act.act : 0
  };
  if (! eri_live_signal_thread__sig_action (sig_th, &args))
    return SYSCALL_SIG_WAIT_RESTART;

  if (user_old_act && ! copy_to_user (th, user_old_act, &old_act.act,
				      sizeof *user_old_act))
    sregs->rax = ERI_EFAULT;
  else sregs->rax = 0;

  if (user_old_act)
    {
      old_act.ver = args.ver;
      syscall_record (th, ERI_SYSCALL_RT_SIGACTION_GET_MAGIC, &old_act);
    }
  else
    syscall_record (th, ERI_SYSCALL_RT_SIGACTION_MAGIC, (void *) args.ver);
  return SYSCALL_DONE;
}

DEFINE_SYSCALL (sigaltstack)
{
  eri_common_syscall_sigaltstack (
		th_sregs (th), th->ctx->ctx.rsp, &th->sig_alt_stack,
		copy_from_user, copy_to_user, th);
  return SYSCALL_DONE;
}

DEFINE_SYSCALL (rt_sigreturn)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct thread_context *th_ctx = th->ctx;

  if (! eri_live_signal_thread__sig_mask_all (sig_th))
    return SYSCALL_SIG_WAIT_RESTART;

  struct eri_stack st = {
    (uint64_t) th->sig_stack, ERI_SS_AUTODISARM, 2 * THREAD_SIG_STACK_SIZE
  };
  struct eri_sigset mask;

  struct eri_common_syscall_rt_sigreturn_args args = {
    &th_ctx->ext, &th_ctx->ctx, &th_ctx->syscall.eregs,
    &st, &mask, &th->sig_alt_stack, copy_from_user, th
  };
  if (! eri_common_syscall_rt_sigreturn (&args)) return SYSCALL_SEG_FAULT;

  eri_live_signal_thread__sig_reset (sig_th, &mask);
  return SYSCALL_DONE;
}

DEFINE_SYSCALL (rt_sigpending)
{
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  if (! eri_common_syscall_valid_rt_sigpending (th->group, sregs))
    return SYSCALL_DONE;

  syscall_signal_thread (th);

  struct eri_syscall_rt_sigpending_record rec = { sregs->rax };
  if (! eri_syscall_is_error (sregs->rax))
    {
      rec.in = io_in (th);
      /* XXX: detect memory corruption in analysis */
      do_copy_from_user (th->ctx, &rec.set,
			 (void *) sregs->rdi, ERI_SIG_SETSIZE);
    }
  syscall_record (th, ERI_SYSCALL_RT_SIGPENDING_MAGIC, &rec);
  return SYSCALL_DONE;
}

static uint32_t
syscall_do_pause (struct eri_live_thread *th)
{
  syscall_sig_wait (th->ctx, 0);
  syscall_record_in (th);
  SYSCALL_RETURN_DONE (th_sregs (th), ERI_EINTR);
}

DEFINE_SYSCALL (pause) { return syscall_do_pause (th); }

DEFINE_SYSCALL (rt_sigsuspend)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  const struct eri_sigset *user_mask = (void *) sregs->rdi;
  uint64_t size = sregs->rsi;

  if (size != ERI_SIG_SETSIZE)
    SYSCALL_RETURN_DONE (sregs, ERI_EINVAL);

  struct eri_sigset mask;
  if (! copy_from_user (th, &mask, user_mask, sizeof mask))
    SYSCALL_RETURN_DONE (sregs, ERI_EFAULT);

  if (! eri_live_signal_thread__sig_tmp_mask_async (sig_th, &mask))
    return SYSCALL_SIG_WAIT_RESTART;

  return syscall_do_pause (th);
}

DEFINE_SYSCALL (rt_sigtimedwait)
{
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  struct thread_context *th_ctx = th->ctx;
  const struct eri_sigset *user_set = (void *) sregs->rdi;
  struct eri_siginfo *user_info = (void *) sregs->rsi;
  const struct eri_timespec *user_timeout = (void *) sregs->rdx;
  uint64_t size = sregs->r10;

  if (size != ERI_SIG_SETSIZE) SYSCALL_RETURN_DONE (sregs, ERI_EINVAL);

  struct eri_sigset set;
  if (! copy_from_user (th, &set, user_set, sizeof set))
    SYSCALL_RETURN_DONE (sregs, ERI_EFAULT);

  struct eri_timespec timeout;
  if (user_timeout
      && ! copy_from_user (th, &timeout, user_timeout, sizeof timeout))
    SYSCALL_RETURN_DONE (sregs, ERI_EFAULT);

  const struct eri_sigset *mask
	= eri_live_signal_thread__get_sig_mask (sig_th);

  struct eri_sigset tmp_mask = *mask;
  eri_sig_diff_set (&tmp_mask, &set);

  eri_sig_and_set (&set, mask);
  eri_atomic_store_rel (&th_ctx->sig_force_deliver, &set);

  eri_assert (eri_live_signal_thread__sig_tmp_mask_async (sig_th, &tmp_mask));

  struct eri_syscall_rt_sigtimedwait_record rec;

  if (! syscall_sig_wait (th_ctx, user_timeout ? &timeout : 0))
    {
      if (eri_live_signal_thread__sig_tmp_mask_async (sig_th, mask))
	{
	  eri_atomic_store (&th_ctx->sig_force_deliver, 0);
	  rec.result = ERI_EAGAIN;
	  goto record;
	}
      syscall_sig_wait (th_ctx, 0);
    }
  eri_atomic_store (&th_ctx->sig_force_deliver, 0);

  struct eri_sigframe *frame = sig_get_frame (th_ctx);
  if (frame->info.sig == ERI_LIVE_SIGNAL_THREAD_SIG_EXIT_GROUP
      || ! eri_sig_set_set (&set, frame->info.sig))
    {
      rec.result = ERI_EINTR;
      goto record;
    }

  rec.result = frame->info.sig;
  if (user_info) rec.info = frame->info;
  else rec.info.sig = 0;

  sig_set_frame (th_ctx, 0);
  eri_live_signal_thread__sig_reset (sig_th, 0);
  if (user_info
      && ! copy_to_user (th, user_info, &rec.info, sizeof *user_info))
    rec.result = ERI_EFAULT;

  if (! eri_syscall_is_error (rec.result) || rec.result == ERI_EINTR)
    rec.in = io_in (th);

record:
  syscall_record (th, ERI_SYSCALL_RT_SIGTIMEDWAIT_MAGIC, &rec);
  SYSCALL_RETURN_DONE (sregs, rec.result);
}

static void
syscall_do_kill (struct eri_live_thread *th)
{
  struct eri_entry_scratch_registers *sregs = th_sregs (th);

  /* XXX: remove unnecessary record (error, sig == 0 etc) */
  struct eri_syscall_kill_record rec = { io_out (th) };
  syscall_signal_thread (th);

  if (! eri_syscall_is_error (sregs->rax)
      && eri_live_signal_thread__signaled (th->sig_th))
    syscall_sig_wait (th->ctx, 0);

  rec.result = sregs->rax;
  syscall_record_kill (th, &rec);
}

DEFINE_SYSCALL (kill) { syscall_do_kill (th); return SYSCALL_DONE; }
DEFINE_SYSCALL (tkill) { syscall_do_kill (th); return SYSCALL_DONE; }
DEFINE_SYSCALL (tgkill) { syscall_do_kill (th); return SYSCALL_DONE; }

DEFINE_SYSCALL (rt_sigqueueinfo)
{
  syscall_do_kill (th);
  return SYSCALL_DONE;
}

DEFINE_SYSCALL (rt_tgsigqueueinfo)
{
  syscall_do_kill (th);
  return SYSCALL_DONE;
}

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
  struct eri_live_thread_group *group = th->group;
  struct eri_entry_scratch_registers *sregs = th_sregs (th);

  int32_t fd = sregs->rdi;
  const struct eri_sigset *user_mask = (void *) sregs->rsi;
  uint64_t size = sregs->rdx;
  int32_t flags = sregs->rax == __NR_signalfd4 ? sregs->r10 : 0;

  if ((flags & ~(ERI_SFD_CLOEXEC | ERI_SFD_NONBLOCK))
      || size != ERI_SIG_SETSIZE)
    SYSCALL_RETURN_DONE (sregs, ERI_EINVAL);

  struct eri_sigset mask;
  if (! copy_from_user (th, &mask, user_mask, sizeof mask))
    SYSCALL_RETURN_DONE (sregs, ERI_EINVAL); /* XXX: from kernel source */

  struct eri_syscall_kill_record rec = { io_out (th) };
  if (fd == -1)
    {
      int32_t sig_fd_flags = flags & ERI_SFD_NONBLOCK;
      flags |= ERI_SFD_NONBLOCK;

      eri_assert_lock (&group->sig_fd_lock);
      rec.result = eri_syscall (signalfd4, fd, &mask, ERI_SIG_SETSIZE, flags);
      if (! eri_syscall_is_error (rec.result))
	sig_fd_alloc_insert (group, rec.result, &mask, sig_fd_flags);
      eri_assert_unlock (&group->sig_fd_lock);
      goto record;
    }

  struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);
  if (! sig_fd)
    {
      rec.result = eri_syscall (signalfd4, fd, &mask,
				  ERI_SIG_SETSIZE, flags);
      eri_assert (rec.result == ERI_EBADF || rec.result == ERI_EINVAL);
      goto record;
    }

  eri_assert_lock (&sig_fd->mask->lock);
  rec.result = eri_syscall (signalfd4, fd, &mask, ERI_SIG_SETSIZE, flags);
  if (! eri_syscall_is_error (rec.result)) sig_fd->mask->mask = mask;
  eri_assert_unlock (&sig_fd->mask->lock);
  eri_assert_unlock (&group->sig_fd_lock);

record:
  syscall_record_kill (th, &rec);
  SYSCALL_RETURN_DONE (sregs, rec.result);
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
  struct eri_live_thread_group *group = th->group;
  int32_t fd = th_sregs (th)->rdi;

  struct eri_syscall_kill_record rec = { io_out (th) };
  struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);

  rec.result = eri_syscall (close, fd);
  if (! sig_fd) goto record;

  if (! eri_syscall_is_error (rec.result))
    sig_fd_remove_free (group, sig_fd);
  eri_assert_unlock (&group->sig_fd_lock);

record:
  syscall_record_kill (th, &rec);
  SYSCALL_RETURN_DONE (th_sregs (th), rec.result);
}

DEFINE_SYSCALL (dup)
{
  struct eri_live_thread_group *group = th->group;
  int32_t fd = th_sregs (th)->rdi;

  struct eri_syscall_kill_record rec = { io_out (th) };
  struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);

  rec.result = eri_syscall (dup, fd);
  if (! sig_fd) goto record;

  if (! eri_syscall_is_error (rec.result))
    sig_fd_copy_insert (group, rec.result, sig_fd);
  eri_assert_unlock (&group->sig_fd_lock);

record:
  syscall_record_kill (th, &rec);
  SYSCALL_RETURN_DONE (th_sregs (th), rec.result);
}

static uint32_t
syscall_do_dup2 (struct eri_live_thread *th)
{
  struct eri_live_thread_group *group = th->group;
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  uint8_t dup3 = sregs->rax == __NR_dup3;
  int32_t fd = sregs->rdi;
  int32_t new_fd = sregs->rsi;
  int32_t flags = dup3 ? sregs->rdx : 0;

  if (fd == new_fd)
    SYSCALL_RETURN_DONE (sregs, dup3 ? ERI_EINVAL : new_fd);

  struct eri_syscall_kill_record rec = { io_out (th) };
  struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);

  rec.result = eri_syscall (dup3, fd, new_fd, flags);
  if (! sig_fd) goto record;

  if (! eri_syscall_is_error (rec.result))
    {
      new_fd = rec.result;
      struct sig_fd *new_sig_fd = sig_fd_rbt_get (group, &new_fd,
						  ERI_RBT_EQ);
      if (new_sig_fd) sig_fd_remove_free (group, new_sig_fd);

      sig_fd_copy_insert (group, new_fd, sig_fd);
    }
  eri_assert_unlock (&group->sig_fd_lock);

record:
  syscall_record_kill (th, &rec);
  SYSCALL_RETURN_DONE (sregs, rec.result);
}

DEFINE_SYSCALL (dup2) { return syscall_do_dup2 (th); }
DEFINE_SYSCALL (dup3) { return syscall_do_dup2 (th); }

SYSCALL_TO_IMPL (name_to_handle_at)
SYSCALL_TO_IMPL (open_by_handle_at)

DEFINE_SYSCALL (fcntl)
{
  struct eri_live_thread_group *group = th->group;
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  int32_t fd = sregs->rdi;
  int32_t cmd = sregs->rsi;

  if (cmd == ERI_F_DUPFD || cmd == ERI_F_DUPFD_CLOEXEC
      || cmd == ERI_F_GETFL || cmd == ERI_F_SETFL)
    {
      struct eri_syscall_kill_record rec = { io_out (th) };
      struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);

      if (! sig_fd)
	{
	  rec.result = eri_syscall (fcntl, fd, cmd, sregs->rdx);
	  goto record_kill;
	}

      if (cmd == ERI_F_SETFL)
	rec.result = eri_syscall (fcntl, fd, cmd,
				  sregs->rdx | ERI_O_NONBLOCK);
      else rec.result = eri_syscall (fcntl, fd, cmd, sregs->rdx);

      if (! eri_syscall_is_error (rec.result))
	{
	  if (cmd == ERI_F_DUPFD || cmd == ERI_F_DUPFD_CLOEXEC)
	    sig_fd_copy_insert (group, rec.result, sig_fd);
	  else if (cmd == ERI_F_GETFL)
	    rec.result &= sig_fd->flags | ~ERI_O_NONBLOCK;
	  else sig_fd->flags = sregs->rdx & ERI_O_NONBLOCK;
	}
      eri_assert_unlock (&group->sig_fd_lock);

    record_kill:
      syscall_record_kill (th, &rec);
      SYSCALL_RETURN_DONE (sregs, rec.result);
    }

  /* TODO: other cmd */
  syscall_syscall (th->ctx);
  return SYSCALL_DONE;
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
  struct eri_live_thread_group *group = th->group;
  struct eri_live_signal_thread *sig_th = th->sig_th;
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  int32_t nr = sregs->rax;
  int32_t fd = sregs->rdi;

  if (nr == __NR_read || nr == __NR_pread64)
    {
      if (internal_range (group, sregs->rsi, sregs->rdx))
	sregs->rsi = 0;
    }
  else
    {
      uint64_t i;
      const struct eri_iovec *user_iov = (void *) sregs->rsi;
      for (i = 0; i < sregs->rdx; ++i)
	{
	  struct eri_iovec iov;
	  if (! copy_from_user (th, &iov, user_iov, sizeof iov)
	      || internal_range (group, (uint64_t) iov.base, iov.len))
	    sregs->rsi = 0;
	}
    }

  struct sig_fd *sig_fd = sig_fd_try_lock (group, fd);
  if (! sig_fd)
    {
      syscall_intr_syscall (th->ctx);
      goto record;
    }

  struct sig_fd_mask *mask = sig_fd->mask;
  eri_atomic_inc (&mask->ref_count);
  eri_barrier ();
  int32_t flags = sig_fd->flags;
  eri_assert_unlock (&group->sig_fd_lock);

  uint64_t a[5] = {
    sregs->rsi, sregs->rdx, sregs->r10, sregs->r8, sregs->r9
  };
  struct eri_live_signal_thread__sig_fd_read_args args = {
    fd, nr, a, &mask->lock, &mask->mask, flags
  };

  uint8_t restart = 1;
  if (eri_live_signal_thread__sig_fd_read (sig_th, &args))
    {
      if (args.result == ERI_EINTR) syscall_sig_wait (th->ctx, 0);

      sregs->rax = args.result;
      restart = 0;
    }

  if (! eri_atomic_dec_fetch_rel (&mask->ref_count))
    eri_assert_mtfree (group->pool, mask);

  if (restart) return SYSCALL_SIG_WAIT_RESTART;

record:
  if (nr == __NR_read || nr == __NR_pread64)
    {
      struct eri_syscall_read_record rec = {
	sregs->rax, io_in (th), (void *) sregs->rsi, copy_from_user, th
      };
      syscall_record (th, ERI_SYSCALL_READ_MAGIC, &rec);
    }
  else
    {
      struct eri_syscall_readv_record rec = {
	sregs->rax, io_in (th), (void *) sregs->rsi, copy_from_user, th
      };
      syscall_record (th, ERI_SYSCALL_READV_MAGIC, &rec);
    }

  return SYSCALL_DONE;
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
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  int32_t nr = sregs->rax;

#define SYSCALL(name) \
  do {									\
    switch (ERI_PASTE (syscall_, name) (th))				\
      {									\
      case SYSCALL_DONE: goto done;					\
      case SYSCALL_SIG_WAIT_RESTART: goto sig_wait_restart;		\
      case SYSCALL_SEG_FAULT: goto seg_fault;				\
      default: eri_assert_unreachable ();				\
      }									\
  } while (0)

  ERI_SYSCALLS (ERI_IF_SYSCALL, nr, SYSCALL)

  sregs->rax = ERI_ENOSYS;
  goto done;

done:
  eri_debug ("%u done\n", nr);
  swallow_single_step (th_ctx);
  if (nr == __NR_rt_sigreturn) return 1;
  sregs->rcx = th_ctx->ext.ret;
  sregs->r11 = sregs->rflags;
  return 0;

sig_wait_restart:
  eri_debug ("sig_wait_restart\n");
  syscall_sig_wait (th_ctx, 0);
  th_ctx->ext.ret = th_ctx->ext.call;
  return 0;

seg_fault:
  eri_debug ("seg_fault\n");
  sregs->rcx = th_ctx->ext.ret;
  sregs->r11 = sregs->rflags;
  th_ctx->ext.ret = th_ctx->ext.call;
  return 0;
}

static void
sig_hand_syscall (struct eri_live_thread *th, struct eri_sigframe *frame,
		  struct eri_ver_sigaction *act)
{
  struct eri_siginfo *info = &frame->info;
  struct eri_ucontext *ctx = &frame->ctx;

  if (eri_si_single_step (info)) return;

  struct thread_context *th_ctx = th->ctx;

  if (sig_access_fault (th_ctx, info, ctx))
    {
      if (th_sregs (th)->rax != __NR_rt_sigreturn) return;

      /* XXX: sig masked all */
      eri_assert (eri_live_thread__sig_digest_act (th, info, act));
      eri_assert (act->act.act == ERI_SIG_ACT_CORE);
      sig_set (th_ctx, frame, act, SIG_HAND_NONE);
      return;
    }

  /* XXX: SIGSYS */
  eri_assert (! eri_si_sync (info));

  /* interruptable but not done the syscall */
  if (th_ctx->syscall.sig_intr && ctx->mctx.rip != th_ctx->syscall.sig_intr)
    {
      ctx->mctx.rax = ERI_EINTR;
      ctx->mctx.rip = th_ctx->syscall.sig_intr;
    }

  sig_set (th_ctx, frame, act, SIG_HAND_NONE);
  if (th_ctx->syscall.wait_sig)
    eri_assert_syscall (futex, &th_ctx->sig_frame, ERI_FUTEX_WAKE, 1);
}

void
sync_async (struct eri_live_thread *th, uint64_t cnt)
{
  swallow_single_step (th->ctx);
  eri_live_thread_recorder__rec_sync_async (th->rec, cnt);
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
		struct eri_ver_sigaction *act)
{
  struct eri_siginfo *info = &frame->info;
  struct eri_ucontext *ctx = &frame->ctx;

  struct thread_context *th_ctx = th->ctx;

  uint8_t intern = internal (th->group, ctx->mctx.rip);
  uint8_t inst = ctx->mctx.rip == th_ctx->ext.ret;
  uint8_t single_step = eri_si_single_step (info);

  if (intern && single_step) return;

  if (intern) eri_assert (! eri_si_sync (info));

  if (single_step && th_ctx->swallow_single_step)
    {
      th_ctx->swallow_single_step = 0;
      return;
    }

  if (eri_si_sync (info) && ! sig_prepare_sync (th, info, act))
    return;

  if (intern)
    {
      ctx->mctx.rcx = th_sregs (th)->rcx;
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
		     struct eri_ver_sigaction *act)
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
  struct eri_live_thread_group *group = th->group;
  /* XXX: always cause sigsegv? */
  if (internal_range (group, mem, size)) mem = 0;
  th_ctx->atomic.idx = lock_atomic (group, mem, size);
  return mem;
}

static uint8_t
updated (uint8_t size, uint64_t old_val, uint64_t val)
{
  switch (size)
   {
   case 0: return (old_val & 0xff) == (val & 0xff);
   case 1: return (old_val & 0xffff) == (val & 0xffff);
   case 2: return (old_val & 0xffffffff) == (val & 0xffffffff);
   case 3:
     return (old_val & 0xffffffffffffffff) == (val & 0xffffffffffffffff);
   default: eri_assert_unreachable ();
   }
}

void
complete_atomic (struct eri_live_thread *th, uint64_t old_val)
{
  struct thread_context *th_ctx = th->ctx;

  uint8_t size = th_ctx->ext.op.args;
  uint16_t code = th_ctx->ext.op.code;
  uint64_t src = th_ctx->ext.atomic.val;
  uint8_t update;
  if (code == _ERS_OP_ATOMIC_STORE || code == _ERS_OP_ATOMIC_XCHG)
    update = updated (size, old_val, src);
  else if (code == _ERS_OP_ATOMIC_INC || code == _ERS_OP_ATOMIC_DEC)
    update = 1;
  else if (code == _ERS_OP_ATOMIC_LOAD) update = 0;
  else if (code == _ERS_OP_ATOMIC_CMPXCHG)
    update = (th_sregs (th)->rflags & ERI_RFLAGS_ZERO_MASK)
		? updated (size, old_val, src) : 0;
  else eri_assert_unreachable ();

  struct atomic_pair ver
	= unlock_atomic (th->group, &th_ctx->atomic.idx, update);
  eri_atomic_store (&th_ctx->atomic.access_end, 0);

  if (code == _ERS_OP_ATOMIC_LOAD || code == _ERS_OP_ATOMIC_XCHG)
    th_ctx->ext.atomic.val = old_val;

  struct eri_live_thread_recorder *th_rec = th->rec;
  if (code == _ERS_OP_ATOMIC_STORE
      || code == _ERS_OP_ATOMIC_INC || code == _ERS_OP_ATOMIC_DEC)
    old_val = 0;
  /* XXX: cmpxchg16b */
  eri_live_thread_recorder__rec_atomic (th_rec, update, &ver.first, old_val);
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
		 struct eri_ver_sigaction *act)
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
		struct eri_ver_sigaction *act)
{
  struct eri_siginfo *info = &frame->info;
  eri_debug ("sig_hand = %u, sig = %u, frame = %lx, rip = %lx\n",
	     th->ctx->ext.op.sig_hand, info->sig,
	     frame, frame->ctx.mctx.rip);

  const void (*hands[]) (
	    struct eri_live_thread *, struct eri_sigframe *,
	    struct eri_ver_sigaction *) = {
#define SIG_HAND_ARRAY_ELT(chand, hand)	hand,
    SIG_HANDS (SIG_HAND_ARRAY_ELT)
  };

  struct eri_ver_sigaction sync_act;
  if (eri_si_sync (info)) act = &sync_act;
  hands[th->ctx->ext.op.sig_hand] (th, frame, act);
}

uint64_t
eri_live_thread__io_out (struct eri_live_thread *th)
{
  return io_out (th);
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
