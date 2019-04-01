#include <public/impl/common.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/atomic.h>
#include <lib/malloc.h>
#include <lib/printf.h>
#include <lib/syscall.h>

#include <common/entry.h>
#include <common/common.h>
#include <common/helper.h>

#include <replay/rtld.h>
#include <replay/thread.h>
#include <replay/thread-local.h>

#define HELPER_STACK_SIZE	(256 * 1024)

enum
{
#define SIG_HAND_ENUM(chand, hand)	chand,
  ERI_ENTRY_THREAD_ENTRY_SIG_HANDS (SIG_HAND_ENUM)
  SIG_HAND_RETURN_TO_USER
};

#define SYNC_ASYNC_TRACE_ASYNC	1
#define SYNC_ASYNC_TRACE_BOTH	2

struct version
{
  uint64_t ver;
  uint64_t wait;
};

static void
version_init (struct version *ver)
{
  ver->ver = 0;
  ver->wait = 0;
}

static void
version_wait (struct version *ver, uint64_t exp)
{
  uint64_t now;
  if ((now = eri_atomic_load (&ver->ver)) >= exp) return;

  eri_atomic_inc (&ver->wait);
  eri_barrier ();
  do
    eri_assert_sys_futex_wait (&ver->ver, now, 0);
  while ((now = eri_atomic_load (&ver->ver)) < exp);
  eri_atomic_dec (&ver->wait);
}

static void
version_update (struct version *ver)
{
  eri_atomic_inc (&ver->ver);
  eri_barrier ();
  if (eri_atomic_load_acq (&ver->wait))
    eri_assert_syscall (futex, &ver->ver, ERI_FUTEX_WAKE, ERI_INT_MAX);
}

static void
version_wait_update (struct version *ver, uint64_t exp)
{
  version_wait (ver, exp);
  version_update (ver);
}

struct thread_group
{
  struct eri_mtpool *pool;

  uint64_t map_start;
  uint64_t map_end;

  const char *path;
  uint64_t stack_size;
  uint64_t file_buf_size;

  struct eri_helper *helper;

  int32_t pid;

  struct version sig_acts[ERI_NSIG];

  struct version *atomic_table;
  uint64_t atomic_table_size;

  struct eri_lock exit_lock;
  uint64_t thread_count;

  int32_t user_pid;

  struct version io;
};

#define THREAD_SIG_STACK_SIZE	(2 * 4096)

struct thread
{
  struct thread_group *group;

  struct thread_context *ctx;

  eri_file_t file;
  uint8_t *file_buf;

  int32_t tid;
  int32_t alive;

  int32_t *clear_user_tid;
  int32_t user_tid;

  struct eri_sigset sig_mask;
  struct eri_stack sig_alt_stack;

  eri_aligned16 uint8_t sig_stack[THREAD_SIG_STACK_SIZE];
  eri_aligned16 uint8_t stack[0];
};

#define th_ctx_sregs(th_ctx)	eri_th_ctx_sregs (th_ctx)
#define th_sregs(th)		th_ctx_sregs ((th)->ctx)

ERI_DEFINE_THREAD_UTILS (struct thread, struct thread_group)

#define assert_magic(th, magic) \
  eri_assert (eri_unserialize_magic ((th)->file) == magic);

static uint8_t
read_user (struct thread *th, const void *src, uint64_t size)
{
  if (! src) return 0;
  if (internal_range (th->group, (uint64_t) src, size)) return 0;
  return do_read_user (th->ctx, src, size);
}

static void
io_in (struct thread *th, uint64_t ver)
{
  version_wait (&th->group->io, ver);
}

static void
io_out (struct thread *th, uint64_t ver)
{
  version_wait_update (&th->group->io, ver);
}

static void sig_handler (int32_t sig, struct eri_siginfo *info,
			 struct eri_ucontext *ctx);

static struct thread_group *
create_group (const struct eri_replay_rtld_args *rtld_args)
{
  struct eri_mtpool *pool = eri_init_mtpool_from_buf (
				rtld_args->buf, rtld_args->buf_size, 1);
  struct thread_group *group
			= eri_assert_malloc (&pool->pool, sizeof *group);
  group->pool = pool;

  group->path = eri_assert_malloc (&pool->pool,
				   eri_strlen (rtld_args->path) + 1);
  eri_strcpy ((void *) group->path, rtld_args->path);
  group->stack_size = rtld_args->stack_size;
  group->file_buf_size = rtld_args->file_buf_size;

  group->pid = eri_assert_syscall (getpid);
  int32_t sig;
  for (sig = 1; sig < ERI_NSIG; ++sig)
    {
      if (! eri_sig_catchable (sig)) continue;

      struct eri_sigaction act = {
	sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_ONSTACK,
	eri_assert_sys_sigreturn
      };
      eri_sig_fill_set (&act.mask);
      eri_assert_sys_sigaction (sig, &act, 0);

      version_init (group->sig_acts + sig - 1);
    }

  eri_init_lock (&group->exit_lock, 0);
  group->thread_count = 1;

  version_init (&group->io);
  return group;
}

static void
destroy_group (struct thread_group *group)
{
  struct eri_pool *pool = &group->pool->pool;
  eri_assert_free (pool, group->atomic_table);
  eri_assert_free (pool, (void *) group->path);
  eri_assert_free (pool, group);
  eri_debug ("%lu\n", pool->used);
  eri_assert_fini_pool (pool);
}

static struct thread *
create (struct thread_group *group, uint64_t id, int32_t *clear_user_tid)
{
  struct thread *th = eri_assert_mtmalloc (group->pool,
				sizeof *th + group->stack_size);
  th->group = group;
  struct thread_context *th_ctx = eri_assert_mtmalloc (group->pool,
	sizeof *th->ctx + eri_entry_thread_entry_text_size (thread_context));
  th->ctx = th_ctx;

  eri_debug ("entry: %lx\n", entry);
  eri_entry_init (&th_ctx->ext, &th_ctx->ctx, thread_context, th_ctx->text,
		  entry, th->stack + group->stack_size);

  th_ctx->access = 0;
  th_ctx->swallow_single_step = 0;

  th_ctx->sync_async_trace = 0;
  th_ctx->atomic_access_fault = 0;
  th_ctx->atomic_ext_return = 0;

  th_ctx->th = th;
  char name[eri_build_path_len (group->path, "t", id)];
  eri_build_path (group->path, "t", id, name);

  uint64_t file_buf_size = group->file_buf_size;
  th->file_buf = eri_assert_mtmalloc (group->pool, file_buf_size);
  th->file = eri_assert_fopen (name, 1, th->file_buf, file_buf_size);

  th->alive = 1;
  th->clear_user_tid = clear_user_tid;

  *(void **) th->sig_stack = th;
  return th;
}

static void
destroy (struct thread *th)
{
  eri_assert_fclose (th->file);
  struct eri_mtpool *pool = th->group->pool;
  eri_assert_mtfree (pool, th->file_buf);
  eri_assert_mtfree (pool, th->ctx);
  eri_assert_mtfree (pool, th);
}

static void
cleanup (void *args)
{
  struct thread *th = args;
  eri_debug ("%lu\n", th->tid);
  eri_assert_sys_futex_wait (&th->alive, 1, 0);
  eri_debug ("destroy %lu\n", th->tid);
  destroy (th);
  eri_debug ("\n");
}

static eri_noreturn void exit (struct thread *th);

static eri_noreturn void
exit (struct thread *th)
{
  eri_debug ("\n");
  struct thread_group *group = th->group;
  eri_assert_lock (&group->exit_lock);
  if (--group->thread_count)
    {
      eri_debug ("exit\n");
      eri_helper__invoke (group->helper, cleanup, th);
      eri_assert_unlock (&group->exit_lock);
      eri_debug ("do exit\n");
      eri_assert_sys_exit (0);
    }

  eri_assert_unlock (&group->exit_lock);

  eri_debug ("exit helper\n");
  eri_helper__exit (group->helper);

  eri_debug ("final exit\n");

  eri_preserve (&group->pool->pool);

  destroy (th);
  destroy_group (group);
  eri_assert_sys_exit (0);
}

static uint8_t
next_record (struct thread *th)
{
  return eri_unserialize_mark (th->file);
}

static eri_noreturn void
async_signal (struct thread *th)
{
  eri_debug ("\n");
  eri_assert_syscall (tgkill, th->group->pid, th->tid, ERI_SIGRTMIN);
  eri_assert_unreachable ();
}

static eri_noreturn void raise (struct thread *th, struct eri_sigframe *frame,
				struct eri_ver_sigaction *act);

static eri_noreturn void
raise (struct thread *th, struct eri_sigframe *frame,
       struct eri_ver_sigaction *act)
{
  int32_t sig = frame->info.sig;
  if (sig == 0) exit (th);

  if (! eri_si_sync (&frame->info) || ! eri_sig_set_set (&th->sig_mask, sig))
    version_wait (th->group->sig_acts + sig - 1, act->ver);

  void *a = act->act.act;
  eri_assert (a && a != ERI_SIG_ACT_STOP);

  if (eri_sig_act_internal_act (a)) exit (th);

  struct eri_sigframe *user_frame = eri_sig_setup_user_frame (
		frame, &act->act, &th->sig_alt_stack, &th->sig_mask,
		copy_to_user, th);
  eri_set_sig_mask (&th->sig_mask, &act->act.mask);

  if (! user_frame) exit (0);

  if (next_record (th) == ERI_ASYNC_RECORD)
    {
      struct thread_context *th_ctx = th->ctx;
      th_ctx->ext.ret = (uint64_t) a;
      th_ctx->ctx.rsp = (uint64_t) user_frame;
      th_sregs (th)->rax = 0;
      th_sregs (th)->rdi = sig;
      th_sregs (th)->rsi = (uint64_t) &user_frame->info;
      th_sregs (th)->rdx = (uint64_t) &user_frame->ctx;
      async_signal (th);
    }

  eri_sig_act (user_frame, a);
}

static eri_noreturn void raise_async (struct thread *th,
				      struct eri_sigframe *frame);

static eri_noreturn void
raise_async (struct thread *th, struct eri_sigframe *frame)
{
  struct eri_signal_record rec;
  eri_unserialize_signal_record (th->file, &rec);
  eri_debug ("%u\n", rec.info.sig);
  io_in (th, rec.in);
  frame->info = rec.info;
  raise (th, frame, &rec.act);
}

static void
set_ctx_from_th_ctx (struct eri_ucontext *ctx,
		     const struct thread_context *th_ctx, uint8_t call)
{
#define SET_SREG(creg, reg)	ctx->mctx.reg = th_ctx_sregs (th_ctx)->reg;
  ERI_ENTRY_FOREACH_SREG (SET_SREG)
#define SET_EREG(creg, reg)	ctx->mctx.reg = th_ctx->eregs.reg;
  ERI_ENTRY_FOREACH_EREG (SET_EREG)
  ctx->mctx.rsp = th_ctx->ctx.rsp;
  ctx->mctx.rbx = th_ctx->ext.rbx;
  ctx->mctx.rip = call ? th_ctx->ext.call : th_ctx->ext.ret;
}

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  struct thread *th = *(void **) ctx->stack.sp;
  struct thread_context *th_ctx = th->ctx;
  struct eri_sigframe *frame
		= eri_struct_of (info, struct eri_sigframe, info);
  if (info->code == ERI_SI_TKILL && info->kill.pid == th->group->pid)
    {
      set_ctx_from_th_ctx (ctx, th_ctx, 0);
      raise_async (th, frame);
    }

  if (! eri_si_sync (info)) return;

  uint16_t code = th_ctx->ext.op.code;
  if (eri_si_single_step (info))
    {
      if (th_ctx->ext.op.sig_hand != SIG_HAND_RETURN_TO_USER) return;
      if (internal (th->group, ctx->mctx.rip)) return;

      if (th_ctx->swallow_single_step)
	{
	  th_ctx->swallow_single_step = 0;
	  return;
	}

      if (code == _ERS_OP_SYNC_ASYNC && th_ctx->sync_async_trace)
	{
	  uint8_t async = 0;
	  if (th_ctx->sync_async_trace_steps)
	    {
	      if (--th_ctx->sync_async_trace_steps == 0)
		{
		  ctx->mctx.rip = th_ctx->ext.call;
		  async = 1;
		}
	    }
	  else if (ctx->mctx.rip != th_ctx->ext.ret) async = 1;

	  if (async)
	    {
	      th_ctx->sync_async_trace = 0;
	      if (th_ctx->sync_async_trace != SYNC_ASYNC_TRACE_BOTH)
		ctx->mctx.rflags &= ~ERI_RFLAGS_TRACE_MASK;
	      raise_async (th, frame);
	    }

	  if (th_ctx->sync_async_trace != SYNC_ASYNC_TRACE_BOTH) return;
	}
    }

  if (sig_access_fault (th_ctx, info, ctx)) return;

  if (code == _ERS_OP_SYNC_ASYNC && ctx->mctx.rip == th_ctx->ext.ret)
    ctx->mctx.rip = th_ctx->ext.call;

  if (th_ctx->atomic_access_fault
      && ctx->mctx.rip == th_ctx->atomic_access_fault)
    {
      th_ctx->atomic_access_fault = 0;
      set_ctx_from_th_ctx (ctx, th_ctx, 1);
    }

  eri_assert (! internal (th->group, ctx->mctx.rip));

  assert_magic (th, ERI_SIGNAL_MAGIC);
  struct eri_ver_sigaction act;
  eri_unserialize_ver_sigaction (th->file, &act);
  raise (th, frame, &act);
}

eri_noreturn void
eri_replay_start (struct eri_replay_rtld_args *rtld_args)
{
  eri_global_enable_debug = rtld_args->debug;
  eri_debug ("%lx, %lx, %u\n",
	     eri_replay_start, rtld_args->buf, rtld_args->buf_size);
  struct thread_group *group = create_group (rtld_args);
  eri_debug ("\n");
  struct thread *th = create (group, 0, 0);
  struct thread_context *th_ctx = th->ctx;

  th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;
  th_ctx->ext.op.args = 0;
  th_ctx->ext.op.code = _ERS_OP_SYSCALL;

  th_ctx->ext.rbx = 0;
#define ZERO_REG(creg, reg, regs)	(regs)->reg = 0;
  ERI_ENTRY_FOREACH_SREG (ZERO_REG, th_sregs (th))
  ERI_ENTRY_FOREACH_EREG (ZERO_REG, &th_ctx->eregs)

  th->tid = group->pid;
  main (th_ctx);
}

static eri_noreturn void async_signal (struct thread *th);

static struct thread_context *
start (struct thread *th, uint8_t next)
{
  eri_debug ("\n");
  struct eri_stack st = {
    (uint64_t) th->sig_stack, ERI_SS_AUTODISARM, THREAD_SIG_STACK_SIZE
  };
  eri_assert_syscall (sigaltstack, &st, 0);

  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_GS, th->ctx);

  if (next == ERI_ASYNC_RECORD) async_signal (th);
  eri_debug ("entry: %lx, %lx\n", th->ctx->ext.entry, th->ctx->ctx.entry);
  return th->ctx;
}

void
start_main (struct thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  eri_assert (next_record (th) == ERI_INIT_RECORD);
  struct eri_init_record rec;
  eri_unserialize_init_record (th->file, &rec);
  eri_assert (rec.ver == 0);

  eri_debug ("rec.rip: %lx, rec.rsp: %lx\n", rec.rip, rec.rsp);

  th_ctx->ext.ret = rec.rip;
  th_ctx->ctx.rsp = rec.rsp;
  th_sregs (th)->rdx = rec.rdx;

  th->sig_mask = rec.sig_mask;
  th->sig_alt_stack = rec.sig_alt_stack;

  struct thread_group *group = th->group;
  group->map_start = rec.start;
  group->map_end = rec.end;

  uint64_t atomic_table_size = rec.atomic_table_size;
  group->atomic_table = eri_assert_calloc (&group->pool->pool,
			sizeof *group->atomic_table * atomic_table_size);
  group->atomic_table_size = atomic_table_size;

  th->user_tid = rec.user_pid;
  group->user_pid = rec.user_pid;

  uint8_t next;
  while ((next = next_record (th)) == ERI_INIT_MAP_RECORD)
    {
      struct eri_init_map_record rec;
      eri_unserialize_init_map_record (th->file, &rec);
      eri_debug ("rec.start: %lx, rec.end: %lx, rec.prot: %u\n",
		 rec.start, rec.end, rec.prot);
      uint64_t size = rec.end - rec.start;
      uint8_t prot = rec.prot;
      uint8_t init_prot = prot | (rec.data_count ? ERI_PROT_WRITE : 0);
      /* XXX: grows_down */
      eri_assert_syscall (mmap, rec.start, size, init_prot,
		ERI_MAP_FIXED | ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
      uint8_t i;
      for (i = 0; i < rec.data_count; ++i)
	{
	  uint64_t start = eri_unserialize_uint64 (th->file);
	  uint64_t end = eri_unserialize_uint64 (th->file);
	  eri_unserialize_uint8_array (th->file, (void *) start, end - start);
	}
      if (init_prot != prot)
	eri_assert_syscall (mprotect, rec.start, size, prot);
    }

  group->helper = eri_helper__start (group->pool, HELPER_STACK_SIZE, 0);

  eri_assert_syscall (set_tid_address, &th->alive);
  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_FS, 0);
  eri_debug ("\n");
  start (th, next);
}

static void
swallow_single_step (struct thread_context *th_ctx)
{
  if (th_ctx_sregs (th_ctx)->rflags & ERI_RFLAGS_TRACE_MASK)
    th_ctx->swallow_single_step = 1;
}

static void
do_atomic_wait (struct thread_group *group, uint64_t slot, uint64_t ver)
{
  uint64_t idx = eri_atomic_hash (slot, group->atomic_table_size);
  version_wait (group->atomic_table + idx, ver);
}

static void
atomic_wait (struct thread_group *group, uint64_t mem, uint8_t size,
	     uint64_t *ver)
{
  do_atomic_wait (group, eri_atomic_slot (mem), ver[0]);
  if (eri_atomic_cross_slot (mem, size))
    do_atomic_wait (group, eri_atomic_slot2 (mem, size), ver[1]);
}

static void
do_atomic_update (struct thread_group *group, uint64_t slot)
{
  uint64_t idx = eri_atomic_hash (slot, group->atomic_table_size);
  version_update (group->atomic_table + idx);
}

static void
atomic_update (struct thread_group *group, uint64_t mem, uint8_t size)
{
  do_atomic_update (group, eri_atomic_slot (mem));
  if (eri_atomic_cross_slot (mem, size))
    do_atomic_update (group, eri_atomic_slot2 (mem, size));
}

#define DEFINE_SYSCALL(name) \
static uint8_t								\
ERI_PASTE (syscall_, name) (struct thread *th)

#define SYSCALL_RETURN(sregs, res, next) \
  do { (sregs)->rax = res; return next; } while (0)
  
#define SYSCALL_TO_IMPL(name) \
DEFINE_SYSCALL (name) { SYSCALL_RETURN (th_sregs (th), ERI_ENOSYS, 0); }

static void
syscall_fetch_in (struct thread *th)
{
  assert_magic (th, ERI_SYSCALL_IN_MAGIC);
  io_in (th, eri_unserialize_uint64 (th->file));
}

/* TODO */

static void
syscall_fetch_out (struct thread *th)
{
  assert_magic (th, ERI_SYSCALL_OUT_MAGIC);
  io_out (th, eri_unserialize_uint64 (th->file));
}

static void
syscall_fetch_kill (struct thread *th,
		    struct eri_syscall_kill_record *rec)
{
  assert_magic (th, ERI_SYSCALL_KILL_MAGIC);
  eri_unserialize_syscall_kill_record (th->file, rec);
  io_out (th, rec->out);
  io_in (th, rec->in);
}

DEFINE_SYSCALL (clone)
{
  eri_debug ("\n");
  assert_magic (th, ERI_SYSCALL_CLONE_MAGIC);
  struct eri_syscall_clone_record rec;
  eri_unserialize_syscall_clone_record (th->file, &rec);

  io_out (th, rec.out);

  struct thread_context *th_ctx = th->ctx;

  if (eri_syscall_is_error (rec.result)) goto done;

  eri_atomic_inc (&th->group->thread_count);
  eri_barrier ();

  int32_t flags = th_sregs (th)->rdi;
  int32_t *user_ptid = (void *) th_sregs (th)->rdx;
  int32_t *user_ctid = (void *) th_sregs (th)->r10;
  if (flags & ERI_CLONE_PARENT_SETTID)
    copy_to_user (th, user_ptid, &rec.result, sizeof *user_ptid);
  if (flags & ERI_CLONE_CHILD_SETTID)
    copy_to_user (th, user_ctid, &rec.result, sizeof *user_ctid);

  int32_t *clear_user_tid = flags & ERI_CLONE_CHILD_CLEARTID ? user_ctid : 0;
  struct thread *cth = create (th->group, rec.id, clear_user_tid);
  struct thread_context *cth_ctx = cth->ctx;
  cth_ctx->ext.op = th_ctx->ext.op;
  cth_ctx->ext.rbx = th_ctx->ext.rbx;
  cth_ctx->ext.ret = th_ctx->ext.ret;
  cth_ctx->ctx.rsp = th_sregs (th)->rsi;
  *th_sregs (cth) = *th_sregs (th);
  th_sregs (cth)->rax = 0;
  cth_ctx->eregs = th_ctx->eregs;

  *(uint64_t *) (cth_ctx->ctx.top - 8) = *(uint64_t *) (th_ctx->ctx.top - 8);

  cth->user_tid = rec.result;
  cth->sig_mask = th->sig_mask;
  cth->sig_alt_stack = th->sig_alt_stack;

  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  void *new_tls = (void *) th_sregs (th)->r8;
  struct eri_sys_clone_args args = {
    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_THREAD
    | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID
    | (new_tls ? ERI_CLONE_SETTLS : 0),

    (void *) (cth_ctx->ctx.top - 8),
    &cth->tid, &cth->alive, new_tls, start, cth,
    (void *) (uint64_t) next_record (cth)
  };

  eri_assert_sys_clone (&args);

  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);
  eri_debug ("%u, %lu\n", rec.result, rec.id);
done:
  SYSCALL_RETURN (th_sregs (th), rec.result, 1);
}

SYSCALL_TO_IMPL (unshare)
SYSCALL_TO_IMPL (kcmp)
SYSCALL_TO_IMPL (fork)
SYSCALL_TO_IMPL (vfork)
SYSCALL_TO_IMPL (setns)

DEFINE_SYSCALL (set_tid_address)
{
  th->clear_user_tid = (void *) th_sregs (th)->rdi;
  SYSCALL_RETURN (th_sregs (th), 0, 0);
}

static uint8_t
read_write_user_tid (struct thread_context *th_ctx, int32_t *user_tid)
{
  uint8_t fault = 0;

  extern uint8_t clear_user_tid_access[];
  extern uint8_t clear_user_tid_access_fault[];
  eri_atomic_store (&th_ctx->access, (uint64_t) clear_user_tid_access);
  th_ctx->access_fault = (uint64_t) clear_user_tid_access_fault;

  asm ("clear_user_tid_access:\n"
       "  orl\t$0, %0\n"
       "  jmp\t1f\n"
       "clear_user_tid_access_fault:\n"
       "  movb\t$1, %b1\n"
       "1:" : "+m" (*user_tid), "+r" (fault) : : "memory");

  eri_atomic_store (&th_ctx->access, 0);
  return ! fault;
}

static void
read_atomic_record (struct thread *th, struct eri_atomic_record *rec)
{
  assert_magic (th, ERI_ATOMIC_MAGIC);
  eri_unserialize_atomic_record (th->file, rec);
}

static eri_noreturn void syscall_do_exit (struct thread *th);

static eri_noreturn void
syscall_do_exit (struct thread *th)
{
  int32_t *user_tid = th->clear_user_tid;
  eri_debug ("%lx, %u, %lu\n", user_tid, th->user_tid,
	     eri_assert_fseek (th->file, 0, ERI_SEEK_CUR));
  if (user_tid && read_write_user_tid (th->ctx, user_tid))
    {
      uint64_t mem = (uint64_t) user_tid;
      uint8_t size = _ERS_ATOMIC_SIZE_l;

      struct eri_atomic_record rec;
      read_atomic_record (th, &rec);
      eri_assert (next_record (th) == ERI_SYNC_RECORD);

      uint64_t ver[2] = { rec.ver[0], rec.ver[1] };
      atomic_wait (th->group, mem, size, ver);

      if (rec.updated)
	{
	  atomic_store (size, mem, 0);
	  atomic_update (th->group, mem, size);
	}
    }

  eri_debug ("\n");
  syscall_fetch_out (th);
  exit (th);
}

DEFINE_SYSCALL (exit) { syscall_do_exit (th); }
DEFINE_SYSCALL (exit_group) { syscall_do_exit (th); }

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

DEFINE_SYSCALL (gettid) { SYSCALL_RETURN (th_sregs (th), th->user_tid, 0); }

DEFINE_SYSCALL (getpid)
{
  SYSCALL_RETURN (th_sregs (th), th->group->user_pid, 0);
}

DEFINE_SYSCALL (getppid)
{
  assert_magic (th, ERI_SYSCALL_RESULT_IN_MAGIC);
  uint64_t rec[2];
  eri_unserialize_uint64_array (th->file, rec, eri_length_of (rec));
  io_in (th, rec[1]);
  SYSCALL_RETURN (th_sregs (th), rec[0], 1);
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
  return 0;
}

SYSCALL_TO_IMPL (quotactl)
SYSCALL_TO_IMPL (acct)

SYSCALL_TO_IMPL (setpriority)
SYSCALL_TO_IMPL (getpriority)

DEFINE_SYSCALL (sched_yield) { SYSCALL_RETURN (th_sregs (th), 0, 0); }

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
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  struct eri_sigset mask;
  struct eri_sigset old_mask = th->sig_mask;
  if (eri_common_syscall_rt_sigprocmask_get (
		sregs, &old_mask, &mask, copy_from_user, th))
    {
      if (sregs->rsi) eri_set_sig_mask (&th->sig_mask, &mask);
      eri_common_syscall_rt_sigprocmask_set (
			  sregs, &old_mask, copy_to_user, th);
    }
  return 0;
}

DEFINE_SYSCALL (rt_sigaction)
{
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  int32_t sig = sregs->rdi;
  const struct eri_sigaction *user_act = (void *) sregs->rsi;
  struct eri_sigaction *user_old_act = (void *) sregs->rdx;

  if (! eri_sig_catchable (sig)) SYSCALL_RETURN (sregs, ERI_EINVAL, 0);

  if (! user_act && ! user_old_act) SYSCALL_RETURN (sregs, 0, 0);

  if (! read_user (th, user_act, sizeof *user_act))
    SYSCALL_RETURN (sregs, ERI_EFAULT, 0);

  uint64_t act_ver;
  if (user_old_act)
    {
      assert_magic (th, ERI_SYSCALL_RT_SIGACTION_MAGIC);
      struct eri_ver_sigaction act;
      eri_unserialize_ver_sigaction (th->file, &act);
      act_ver = act.ver;

      sregs->rax = ! copy_to_user (th, user_old_act, &act,
				   sizeof *user_old_act) ? ERI_EFAULT : 0;
    }
  else
    {
      assert_magic (th, ERI_SYSCALL_RT_SIGACTION_SET_MAGIC);
      act_ver = eri_unserialize_uint64 (th->file);
      sregs->rax = 0;
    }

  if (user_act || ! eri_syscall_is_error (sregs->rax))
    version_wait (th->group->sig_acts + sig - 1, act_ver);
  if (user_act) version_update (th->group->sig_acts + sig - 1);
  return 1;
}

DEFINE_SYSCALL (sigaltstack)
{
  eri_common_syscall_sigaltstack (
		th_sregs (th), th->ctx->ctx.rsp, &th->sig_alt_stack,
		copy_from_user, copy_to_user, th);
  return 0;
}

DEFINE_SYSCALL (rt_sigreturn)
{
  struct thread_context *th_ctx = th->ctx;
  struct eri_stack st = {
    (uint64_t) th->sig_stack, ERI_SS_AUTODISARM, THREAD_SIG_STACK_SIZE
  };
  struct eri_common_syscall_rt_sigreturn_args args = {
    &th_ctx->ext, &th_ctx->ctx, &th_ctx->eregs,
    &st, &th->sig_mask, &th->sig_alt_stack, copy_from_user, th
  };

  if (! eri_common_syscall_rt_sigreturn (&args)) exit (th);
  return 0;
}

DEFINE_SYSCALL (rt_sigpending)
{
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  if (! eri_common_syscall_valid_rt_sigpending (sregs))
    return 0;

  assert_magic (th, ERI_SYSCALL_RT_SIGPENDING_MAGIC);
  struct eri_syscall_rt_sigpending_record rec;
  eri_unserialize_syscall_rt_sigpending_record (th->file, &rec);

  if (! eri_syscall_is_error (rec.result))
    {
      io_in (th, rec.in);
      *(struct eri_sigset *) sregs->rdi = rec.set;
    }
  SYSCALL_RETURN (sregs, rec.result, 1);
}

static void
syscall_do_pause (struct thread *th)
{
  syscall_fetch_in (th);
  th_sregs (th)->rax = ERI_EINTR;
}

DEFINE_SYSCALL (pause) { syscall_do_pause (th); return 1; }

DEFINE_SYSCALL (rt_sigsuspend)
{
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  const struct eri_sigset *user_mask = (void *) sregs->rdi;
  uint64_t size = sregs->rsi;

  if (size != ERI_SIG_SETSIZE) SYSCALL_RETURN (sregs, ERI_EINVAL, 0);

  if (! read_user (th, user_mask, sizeof *user_mask))
    SYSCALL_RETURN (sregs, ERI_EFAULT, 0);

  syscall_do_pause (th);
  return 1;
}

DEFINE_SYSCALL (rt_sigtimedwait)
{
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  const struct eri_sigset *user_set = (void *) sregs->rdi;
  struct eri_siginfo *user_info = (void *) sregs->rsi;
  const struct eri_timespec *user_timeout = (void *) sregs->rdx;
  uint64_t size = sregs->r10;

  if (size != ERI_SIG_SETSIZE) SYSCALL_RETURN (sregs, ERI_EINVAL, 0);

  if (! read_user (th, user_set, sizeof *user_set)
      || (user_timeout
	  && ! read_user (th, user_timeout, sizeof *user_timeout)))
    SYSCALL_RETURN (sregs, ERI_EFAULT, 0);

  struct eri_syscall_rt_sigtimedwait_record rec;
  assert_magic (th, ERI_SYSCALL_RT_SIGTIMEDWAIT_MAGIC);
  eri_unserialize_syscall_rt_sigtimedwait_record (th->file, &rec);

  if (! eri_syscall_is_error (rec.result) || rec.result == ERI_EINTR)
    io_in (th, rec.in);

  if (user_info && ! eri_syscall_is_error (rec.result))
    *user_info = rec.info;
  SYSCALL_RETURN (sregs, rec.result, 1);
}

static void
syscall_do_kill (struct thread *th)
{
  struct eri_syscall_kill_record rec;
  syscall_fetch_kill (th, &rec);
  th_sregs (th)->rax = rec.result;
}

DEFINE_SYSCALL (kill) { syscall_do_kill (th); return 1; }
DEFINE_SYSCALL (tkill) { syscall_do_kill (th); return 1; }
DEFINE_SYSCALL (tgkill) { syscall_do_kill (th); return 1; }
DEFINE_SYSCALL (rt_sigqueueinfo) { syscall_do_kill (th); return 1; }
DEFINE_SYSCALL (rt_tgsigqueueinfo) { syscall_do_kill (th); return 1; }

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

static uint8_t
syscall_do_signalfd (struct thread *th)
{
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  const struct eri_sigset *user_mask = (void *) sregs->rsi;
  uint64_t size = sregs->rdx;
  int32_t flags = sregs->rax == __NR_signalfd4 ? sregs->r10 : 0;

  if ((flags & ~(ERI_SFD_CLOEXEC | ERI_SFD_NONBLOCK))
      || size != ERI_SIG_SETSIZE
      || ! read_user (th, user_mask, sizeof *user_mask))
    SYSCALL_RETURN (sregs, ERI_EINVAL, 0);

  struct eri_syscall_kill_record rec;
  syscall_fetch_kill (th, &rec);
  SYSCALL_RETURN (sregs, rec.result, 1);
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

DEFINE_SYSCALL (close) { syscall_do_kill (th); return 1; }

DEFINE_SYSCALL (dup) { syscall_do_kill (th); return 1; }
DEFINE_SYSCALL (dup2) { syscall_do_kill (th); return 1; }
DEFINE_SYSCALL (dup3) { syscall_do_kill (th); return 1; }

SYSCALL_TO_IMPL (name_to_handle_at)
SYSCALL_TO_IMPL (open_by_handle_at)

DEFINE_SYSCALL (fcntl)
{
  int32_t cmd = th_sregs (th)->rsi;
  if (cmd == ERI_F_DUPFD || cmd == ERI_F_DUPFD_CLOEXEC
      || cmd == ERI_F_GETFL || cmd == ERI_F_SETFL)
    {
      syscall_do_kill (th);
      return 1;
    }

  /* TODO: other cmd */
  return 0;
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

static uint8_t
syscall_do_read (struct thread *th)
{
  struct eri_entry_scratch_registers *sregs = th_sregs (th);
  int32_t nr = sregs->rax;
  /* XXX: detect memory corruption in analysis */
  if (nr == __NR_read || nr == __NR_pread64)
    {
      assert_magic (th, ERI_SYSCALL_READ_MAGIC);
      struct eri_syscall_read_record rec = { .buf = (void *) sregs->rsi };
      eri_unserialize_syscall_read_record (th->file, &rec);
      io_in (th, rec.in);
      SYSCALL_RETURN (sregs, rec.result, 1);
    }
  else
    {
      struct eri_iovec *user_iov = (void *) sregs->rsi;
      int32_t iovcnt = sregs->rdx;
      if (iovcnt > ERI_UIO_MAXIOV) SYSCALL_RETURN (sregs, ERI_EINVAL, 0);
      if (! read_user (th, user_iov, sizeof *user_iov * iovcnt))
	SYSCALL_RETURN (sregs, ERI_EFAULT, 0);

      assert_magic (th, ERI_SYSCALL_READV_MAGIC);
      struct eri_syscall_readv_record rec = { .iov = user_iov };
      eri_unserialize_syscall_readv_record (th->file, &rec);
      io_in (th, rec.in);
      SYSCALL_RETURN (sregs, rec.result, 1);
    }
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

SYSCALL_TO_IMPL (remap_file_pages) /* deprecated */

static uint64_t
syscall (struct thread *th)
{
  struct thread_context *th_ctx = th->ctx;

  int32_t nr = th_sregs (th)->rax;
  eri_debug ("%u\n", nr);

  th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;

  uint8_t next = 0;
  th_sregs (th)->rax = ERI_ENOSYS;
  th_sregs (th)->rcx = th_ctx->ext.ret;
  th_sregs (th)->r11 = th_sregs (th)->rflags;

#define SYSCALL(name)	next = ERI_PASTE (syscall_, name) (th)
  ERI_SYSCALLS (ERI_IF_SYSCALL, nr, SYSCALL)

  if (next && next_record (th) == ERI_ASYNC_RECORD) async_signal (th);

  swallow_single_step (th_ctx);
  return nr == __NR_rt_sigreturn;
}

static void
sync_async (struct thread *th)
{
  eri_assert (eri_unserialize_magic (th->file) == ERI_SYNC_ASYNC_MAGIC);
  uint64_t steps = eri_unserialize_uint64 (th->file);

  struct thread_context *th_ctx = th->ctx;
  th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;

  swallow_single_step (th_ctx);

  if (next_record (th) != ERI_ASYNC_RECORD) return;

  th_ctx->sync_async_trace
		= (th_sregs (th)->rflags & ERI_RFLAGS_TRACE_MASK)
			? SYNC_ASYNC_TRACE_BOTH : SYNC_ASYNC_TRACE_ASYNC;
  th_ctx->sync_async_trace_steps = steps;
  /* XXX: this can be slow with large repeats... */
  th_sregs (th)->rflags |= ERI_RFLAGS_TRACE_MASK;
}

static void
atomic_read_write_user (struct thread *th, uint64_t mem,
			uint8_t size, uint8_t read_only)
{
  if (internal_range (th->group, mem, size)) mem = 0;

  (read_only ? do_atomic_read_user
	     : do_atomic_read_write_user) (th->ctx, mem, size);
}

static void
atomic (struct thread *th)
{
  struct thread_context *th_ctx = th->ctx;

  if (th_ctx->atomic_ext_return)
    {
      th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;
      th_ctx->ext.ret = th_ctx->ext.atomic.ret;
      th_ctx->atomic_ext_return = 0;
    }
  else
    {
      uint16_t code = th_ctx->ext.op.code;
      uint64_t mem = th_ctx->ext.atomic.mem;
      uint8_t size = th_ctx->ext.op.args;
      atomic_read_write_user (th, mem, size, code == _ERS_OP_ATOMIC_LOAD);

      struct eri_atomic_record rec;
      read_atomic_record (th, &rec);

      uint8_t updated = rec.updated;
      uint64_t ver[2] = { rec.ver[0], rec.ver[1] };
      uint64_t old_val = rec.val;

      atomic_wait (th->group, mem, size, ver);

      uint64_t val = th_ctx->ext.atomic.val;
      if (code == _ERS_OP_ATOMIC_STORE && updated)
	{
	  atomic_store (size, mem, val);
	  atomic_update (th->group, mem, size);
	}

      if (code == _ERS_OP_ATOMIC_INC || code == _ERS_OP_ATOMIC_DEC)
	{
	  eri_assert (updated);
	  (code == _ERS_OP_ATOMIC_INC ? atomic_inc : atomic_dec) (size, mem,
						&th_sregs (th)->rflags);
	  atomic_update (th->group, mem, size);
	}

      if (code == _ERS_OP_ATOMIC_XCHG && updated)
	{
	  atomic_store (mem, size, val);
	  atomic_update (th->group, mem, size);
	}

      if (code == _ERS_OP_ATOMIC_CMPXCHG)
	{
	  atomic_cmpxchg_regs (size, &th_sregs (th)->rax,
			       &th_sregs (th)->rflags, old_val);
	  if ((th_sregs (th)->rflags & ERI_RFLAGS_ZERO_MASK) && updated)
	    {
	      atomic_store (mem, size, val);
	      atomic_update (th->group, mem, size);
	    }
	}

      if (code == _ERS_OP_ATOMIC_LOAD || code == _ERS_OP_ATOMIC_XCHG)
	th->ctx->ext.atomic.val = old_val;

      if (code == _ERS_OP_ATOMIC_LOAD || code == _ERS_OP_ATOMIC_XCHG)
	th_ctx->atomic_ext_return = 1;
      else
	th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;
    }

  if (next_record (th) == ERI_ASYNC_RECORD) async_signal (th);
}

uint64_t
relax (struct thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  eri_debug ("%u\n", th_ctx->ext.op.code);
  if (th_ctx->ext.op.code == _ERS_OP_SYSCALL) return syscall (th);
  (th_ctx->ext.op.code == _ERS_OP_SYNC_ASYNC ? sync_async : atomic) (th);
  return 0;
}
