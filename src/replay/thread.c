#include <compiler.h>

#include <common.h>
#include <entry.h>
#include <helper.h>
#include <record.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/atomic.h>
#include <lib/malloc.h>
#include <lib/printf.h>
#include <lib/syscall.h>

#include <public/common.h>
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

struct atomic_table_slot
{
  uint64_t ver;
  uint64_t wait;
};

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

  struct eri_sig_act sig_acts[ERI_NSIG - 1];

  struct atomic_table_slot *atomic_table;
  uint64_t atomic_table_size;

  struct eri_lock exit_lock;
  uint64_t thread_count;

  int32_t user_pid;
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

ERI_DEFINE_THREAD_UTILS (struct thread)

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
  eri_sig_init_acts (group->sig_acts, sig_handler);

  eri_init_lock (&group->exit_lock, 0);
  group->thread_count = 1;
  return group;
}

static void
destroy_group (struct thread_group *group)
{
  struct eri_pool *pool = &group->pool->pool;
  eri_assert_free (pool, (void *) group->path);
  eri_assert_free (pool, group);
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
  eri_assert_fopen (name, 1, &th->file, th->file_buf, file_buf_size);

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
  eri_assert_mtfree (pool, th->ctx);
  eri_assert_mtfree (pool, th);
}

static void
cleanup (void *args)
{
  struct thread *th = args;
  eri_assert_sys_futex_wait (&th->alive, 1, 0);
  destroy (th);
}

static eri_noreturn void exit (struct thread *th);

static eri_noreturn void
exit (struct thread *th)
{
  struct thread_group *group = th->group;
  eri_assert_lock (&group->exit_lock);
  if (--group->thread_count)
    {
      eri_helper__invoke (group->helper, cleanup, th);
      eri_assert_unlock (&group->exit_lock);
      eri_assert_sys_exit (0);
    }

  eri_assert_unlock (&group->exit_lock);

  eri_helper__exit (group->helper);

  eri_preserve (&group->pool->pool);

  destroy (th);
  destroy_group (group);
  eri_assert_sys_exit (0);
}

static uint8_t
next_record (struct thread *th)
{
  uint8_t next;
  eri_assert_fread (th->file, &next, sizeof next, 0);
  return next;
}

static eri_noreturn void raise (struct thread *th, struct eri_siginfo *info,
				struct eri_ucontext *ctx);

static eri_noreturn void
raise (struct thread *th, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (info->sig == 0) exit (th);

  struct eri_sigaction act;
  eri_sig_get_act (th->group->sig_acts, info->sig, &act);
  eri_sig_digest_act (info, &th->sig_mask, &act);

  eri_assert (act.act && act.act != ERI_SIG_ACT_STOP);

  if (eri_sig_act_internal_act (act.act)) exit (th);

  struct eri_sigframe *user_frame = eri_sig_setup_user_frame (
		eri_struct_of (ctx, struct eri_sigframe, ctx), &act,
		&th->sig_alt_stack, &th->sig_mask, copy_to_user, th);

  if (! user_frame) exit (0);

  if (next_record (th) == ERI_ASYNC_RECORD)
    {
      /* TODO: next_record (th) */
    }

  eri_sig_act (user_frame, act.act);
}

static eri_noreturn void raise_async (struct thread *th,
				      struct eri_ucontext *ctx);

static eri_noreturn void
raise_async (struct thread *th, struct eri_ucontext *ctx)
{
  struct eri_siginfo info;
  eri_assert_fread (th->file, &info, sizeof info, 0);
  raise (th, &info, ctx);
}

static void
set_ctx_from_th_ctx (struct eri_ucontext *ctx,
		     const struct thread_context *th_ctx, uint8_t call)
{
#define SET_SREG(creg, reg)	ctx->mctx.reg = th_ctx->ctx.sregs.reg;
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
  if (info->code == ERI_SI_TKILL && info->kill.pid == th->group->pid)
    {
      set_ctx_from_th_ctx (ctx, th_ctx, 0);
      raise_async (th, ctx);
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
	      raise_async (th, ctx);
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

  raise (th, info, ctx);
}

eri_noreturn void
eri_replay_start (struct eri_replay_rtld_args *rtld_args)
{
  struct thread_group *group = create_group (rtld_args);
  struct thread *th = create (group, 0, 0);
  struct thread_context *th_ctx = th->ctx;

  th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;
  th_ctx->ext.op.args = 0;
  th_ctx->ext.op.code = _ERS_OP_SYSCALL;

  th_ctx->ext.rbx = 0;
#define ZERO_REG(creg, reg, regs)	(regs)->reg = 0;
  ERI_ENTRY_FOREACH_SREG (ZERO_REG, &th_ctx->ctx.sregs)
  ERI_ENTRY_FOREACH_EREG (ZERO_REG, &th_ctx->eregs)

  th->tid = group->pid;
  main (th_ctx);
}

static eri_noreturn void async_signal (struct thread *th);

static eri_noreturn void
async_signal (struct thread *th)
{
  eri_assert_syscall (tgkill, th->group->pid, th->tid, ERI_SIGRTMIN);
  eri_assert_unreachable ();
}

static struct thread_context *
start (struct thread *th, uint8_t next)
{
  struct eri_stack st = {
    (uint64_t) th->sig_stack, ERI_SS_AUTODISARM, THREAD_SIG_STACK_SIZE
  };
  eri_assert_syscall (sigaltstack, &st, 0);

  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  eri_assert_syscall (arch_prctl, ERI_ARCH_SET_GS, th->ctx);

  if (next == ERI_ASYNC_RECORD) async_signal (th);
  return th->ctx;
}

void
start_main (struct thread *th)
{
  struct thread_context *th_ctx = th->ctx;
  struct eri_marked_init_record init;
  eri_assert_fread (th->file, &init, sizeof init, 0);
  eri_assert (init.mark == ERI_INIT_RECORD);

  th_ctx->ext.ret = init.rec.rip;
  th_ctx->ctx.rsp = init.rec.rsp;
  th_ctx->ctx.sregs.rdx = init.rec.rdx;

  th->sig_mask = init.rec.sig_mask;
  th->sig_alt_stack = init.rec.sig_alt_stack;

  struct thread_group *group = th->group;
  group->map_start = init.rec.start;
  group->map_end = init.rec.end;

  uint64_t atomic_table_size = init.rec.atomic_table_size;
  group->atomic_table = eri_assert_calloc (&group->pool->pool,
			sizeof *group->atomic_table * atomic_table_size);
  group->atomic_table_size = atomic_table_size;

  th->user_tid = init.rec.user_pid;
  group->user_pid = init.rec.user_pid;

  uint8_t next;
  while ((next = next_record (th)) == ERI_INIT_MAP_RECORD)
    {
      struct eri_init_map_record init_map;
      eri_assert_fread (th->file, &init_map, sizeof init_map, 0);
      uint64_t size = init_map.end - init_map.start;
      uint8_t prot = init_map.prot;
      uint8_t init_prot
		= prot | (init_map.data_count ? ERI_PROT_WRITE : 0);
      /* XXX: grows_down */
      eri_assert_syscall (mmap, init_map.start, size, init_prot,
		ERI_MAP_FIXED | ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
      uint8_t i;
      for (i = 0; i < init_map.data_count; ++i)
	{
	  struct eri_init_map_data_record data;
	  eri_assert_fread (th->file, &data, sizeof data, 0);
	  eri_assert_fread (th->file, (void *) data.start,
			    data.end - data.start, 0);
	}
      if (init_prot != prot)
	eri_assert_syscall (mprotect, init_map.start, size, prot);
    }

  group->helper = eri_helper__start (group->pool, HELPER_STACK_SIZE, 0);

  start (th, next);
}

static void
swallow_single_step (struct thread_context *th_ctx)
{
  if (th_ctx->ctx.sregs.rflags & ERI_RFLAGS_TRACE_MASK)
    th_ctx->swallow_single_step = 1;
}

static void
do_atomic_wait (struct thread_group *group, uint64_t slot, uint64_t ver)
{
  uint64_t idx = eri_atomic_hash (slot, group->atomic_table_size);
  struct atomic_table_slot *tab = group->atomic_table + idx;

  uint64_t now;
  if ((now = eri_atomic_load (&tab->ver)) >= ver) return;

  eri_atomic_inc (&tab->wait);
  eri_barrier ();
  do
    eri_assert_sys_futex_wait (&tab->ver, now, 0);
  while ((now = eri_atomic_load (&tab->ver)) < ver);
  eri_atomic_dec (&tab->wait);
}

static void
atomic_wait (struct thread_group *group, uint64_t mem, uint8_t size,
	     uint8_t updated, uint64_t *ver)
{
  do_atomic_wait (group, eri_atomic_slot (mem), ver[0] - updated);
  if (eri_atomic_cross_slot (mem, size))
    do_atomic_wait (group, eri_atomic_slot2 (mem, size), ver[1] - updated);
}

static void
do_atomic_update (struct thread_group *group, uint64_t slot)
{
  uint64_t idx = eri_atomic_hash (slot, group->atomic_table_size);
  struct atomic_table_slot *tab = group->atomic_table + idx;
  eri_atomic_inc (&tab->ver);
  eri_barrier ();
  if (eri_atomic_load_acq (&tab->wait))
    eri_assert_syscall (futex, &tab->ver, ERI_FUTEX_WAKE, ERI_INT_MAX);
}

static void
atomic_update (struct thread_group *group, uint64_t mem, uint8_t size)
{
  do_atomic_update (group, eri_atomic_slot (mem));
  if (eri_atomic_cross_slot (mem, size))
    do_atomic_update (group, eri_atomic_slot2 (mem, size));
}

#define DEFINE_SYSCALL(name) \
static void								\
ERI_PASTE (syscall_, name) (struct thread *th)

#define SYSCALL_TO_IMPL(name)	DEFINE_SYSCALL (name) { }

DEFINE_SYSCALL (clone)
{
  struct eri_syscall_clone_record rec;
  eri_assert_fread (th->file, &rec, sizeof rec, 0);
  eri_assert (rec.magic == ERI_SYSCALL_CLONE_MAGIC);

  struct thread_context *th_ctx = th->ctx;

  uint64_t result = th_ctx->ctx.sregs.rax = rec.result;
  if (eri_syscall_is_error (result)) return;

  eri_atomic_inc (&th->group->thread_count);
  eri_barrier ();

  int32_t flags = th_ctx->ctx.sregs.rdi;
  int32_t *user_ptid = (void *) th_ctx->ctx.sregs.rdx;
  int32_t *user_ctid = (void *) th_ctx->ctx.sregs.r10;
  if (flags & ERI_CLONE_PARENT_SETTID)
    copy_to_user (th, user_ptid, &result, sizeof *user_ptid);
  if (flags & ERI_CLONE_CHILD_SETTID)
    copy_to_user (th, user_ctid, &result, sizeof *user_ctid);

  int32_t *clear_user_tid = flags & ERI_CLONE_CHILD_CLEARTID ? user_ctid : 0;
  struct thread *cth = create (th->group, rec.id, clear_user_tid);
  struct thread_context *cth_ctx = cth->ctx;
  cth_ctx->ext.op = th_ctx->ext.op;
  cth_ctx->ext.rbx = th_ctx->ext.rbx;
  cth_ctx->ext.ret = th_ctx->ext.ret;
  cth_ctx->ctx.rsp = th_ctx->ctx.sregs.rsi;
  cth_ctx->ctx.sregs = th_ctx->ctx.sregs;
  cth_ctx->ctx.sregs.rax = 0;
  cth_ctx->eregs = th_ctx->eregs;

  *(uint64_t *) (cth_ctx->ctx.top - 8) = *(uint64_t *) (th_ctx->ctx.top - 8);

  cth->user_tid = result;
  cth->sig_mask = th->sig_mask;
  cth->sig_alt_stack = th->sig_alt_stack;

  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);

  void *new_tls = (void *) th_ctx->ctx.sregs.r8;
  struct eri_sys_clone_args args = {
    ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SYSVSEM
    | ERI_CLONE_SIGHAND | ERI_CLONE_THREAD
    | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID
    | (new_tls ? ERI_CLONE_SETTLS : 0),

    (void *) (cth_ctx->ctx.top - 8),
    &cth->tid, &cth->alive, new_tls, start, cth
  };

  eri_assert_sys_clone (&args);

  eri_sig_empty_set (&mask);
  eri_assert_sys_sigprocmask (&mask, 0);
}

SYSCALL_TO_IMPL (unshare)
SYSCALL_TO_IMPL (kcmp)
SYSCALL_TO_IMPL (fork)
SYSCALL_TO_IMPL (vfork)
SYSCALL_TO_IMPL (setns)

DEFINE_SYSCALL (set_tid_address)
{
  th->clear_user_tid = (void *) th->ctx->ctx.sregs.rdi;
  th->ctx->ctx.sregs.rax = 0;
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
  eri_assert_fread (th->file, rec, sizeof *rec, 0);
  eri_assert (rec->magic == ERI_ATOMIC_MAGIC);
}

static void
syscall_do_exit (struct thread *th)
{
  int32_t *user_tid = th->clear_user_tid;
  if (user_tid && read_write_user_tid (th->ctx, user_tid))
    {
      uint64_t mem = (uint64_t) user_tid;
      uint8_t size = _ERS_ATOMIC_SIZE_l;

      struct eri_atomic_record rec;
      read_atomic_record (th, &rec);

      uint64_t ver[2] = { rec.ver[0], rec.ver[1] };
      atomic_wait (th->group, mem, size, rec.updated, ver);

      if (rec.updated)
	{
	  atomic_store (size, mem, 0);
	  atomic_update (th->group, mem, size);
	}
    }
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

DEFINE_SYSCALL (gettid) { th->ctx->ctx.sregs.rax = th->user_tid; }
DEFINE_SYSCALL (getpid) { th->ctx->ctx.sregs.rax = th->group->user_pid; }

SYSCALL_TO_IMPL (getppid)
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
SYSCALL_TO_IMPL (arch_prctl)

SYSCALL_TO_IMPL (quotactl)
SYSCALL_TO_IMPL (acct)

SYSCALL_TO_IMPL (setpriority)
SYSCALL_TO_IMPL (getpriority)
SYSCALL_TO_IMPL (sched_yield)
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
  struct eri_entry_scratch_registers *sregs = &th->ctx->ctx.sregs;
  struct eri_sigset old_mask = th->sig_mask;
  if (! eri_common_syscall_rt_sigprocmask_get (
		sregs, &old_mask, &th->sig_mask, copy_from_user, th))
    return;

  eri_common_syscall_rt_sigprocmask_set (
			sregs, &old_mask, copy_to_user, th);
}

DEFINE_SYSCALL (rt_sigaction)
{
  struct eri_entry_scratch_registers *sregs = &th->ctx->ctx.sregs;
  struct eri_sigaction act;
  if (! eri_common_syscall_rt_sigaction_get (
				sregs, &act, copy_from_user, th))
    return;

  uint8_t user_act = !! sregs->rsi;
  uint8_t user_old_act = !! sregs->rdx;
  if (! user_act && ! user_old_act)
    {
      sregs->rax = 0;
      return;
    }

  int32_t sig = sregs->rdi;
  struct eri_sig_act *sig_acts = th->group->sig_acts;
  struct eri_sigaction old_act;
  if (user_act)
    eri_sig_set_act (sig_acts, sig, &act, user_old_act ? &old_act : 0);
  else eri_sig_get_act (sig_acts, sig, &old_act);

  eri_common_syscall_rt_sigaction_set (sregs, &old_act, copy_to_user, th);
}

DEFINE_SYSCALL (sigaltstack)
{
  struct thread_context *th_ctx = th->ctx;
  eri_common_syscall_sigaltstack (
		&th_ctx->ctx.sregs, th_ctx->ctx.rsp, &th->sig_alt_stack,
		copy_from_user, copy_to_user, th);
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
}

SYSCALL_TO_IMPL (rt_sigpending)

SYSCALL_TO_IMPL (pause)
SYSCALL_TO_IMPL (rt_sigtimedwait)
SYSCALL_TO_IMPL (rt_sigsuspend)

SYSCALL_TO_IMPL (kill)
SYSCALL_TO_IMPL (tkill)
SYSCALL_TO_IMPL (tgkill)
SYSCALL_TO_IMPL (rt_sigqueueinfo)
SYSCALL_TO_IMPL (rt_tgsigqueueinfo)

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

SYSCALL_TO_IMPL (signalfd)
SYSCALL_TO_IMPL (signalfd4)
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
SYSCALL_TO_IMPL (close)

SYSCALL_TO_IMPL (dup)
SYSCALL_TO_IMPL (dup2)
SYSCALL_TO_IMPL (dup3)

SYSCALL_TO_IMPL (name_to_handle_at)
SYSCALL_TO_IMPL (open_by_handle_at)

SYSCALL_TO_IMPL (fcntl)
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

SYSCALL_TO_IMPL (read)
SYSCALL_TO_IMPL (pread64)
SYSCALL_TO_IMPL (readv)
SYSCALL_TO_IMPL (preadv)
SYSCALL_TO_IMPL (preadv2)
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

  int32_t nr = th_ctx->ctx.sregs.rax;

  th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;

  th_ctx->ctx.sregs.rax = ERI_ENOSYS;
  th_ctx->ctx.sregs.rcx = th_ctx->ext.ret;
  th_ctx->ctx.sregs.r11 = th_ctx->ctx.sregs.rflags;

#define SYSCALL(name)	ERI_PASTE (syscall_, name) (th)
  ERI_SYSCALLS (ERI_IF_SYSCALL, nr, SYSCALL)

  if (next_record (th) == ERI_ASYNC_RECORD) async_signal (th);

  swallow_single_step (th_ctx);
  return nr == __NR_rt_sigreturn;
}

static void
sync_async (struct thread *th)
{
  struct eri_sync_async_record sync;
  eri_assert_fread (th->file, &sync, sizeof sync, 0);
  eri_assert (sync.magic == ERI_SYNC_ASYNC_MAGIC);

  struct thread_context *th_ctx = th->ctx;
  th_ctx->ext.op.sig_hand = SIG_HAND_RETURN_TO_USER;

  swallow_single_step (th_ctx);

  if (next_record (th) != ERI_ASYNC_RECORD) return;

  th_ctx->sync_async_trace
		= (th_ctx->ctx.sregs.rflags & ERI_RFLAGS_TRACE_MASK)
			? SYNC_ASYNC_TRACE_BOTH : SYNC_ASYNC_TRACE_ASYNC;
  th_ctx->sync_async_trace_steps = sync.steps;
  /* XXX: this can be slow with large repeats... */
  th_ctx->ctx.sregs.rflags |= ERI_RFLAGS_TRACE_MASK;
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

      atomic_wait (th->group, mem, size, updated, ver);

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
						&th_ctx->ctx.sregs.rflags);
	  atomic_update (th->group, mem, size);
	}

      if (code == _ERS_OP_ATOMIC_XCHG && updated)
	{
	  atomic_store (mem, size, val);
	  atomic_update (th->group, mem, size);
	}

      if (code == _ERS_OP_ATOMIC_CMPXCHG)
	{
	  atomic_cmpxchg_regs (size, &th_ctx->ctx.sregs.rax,
			       &th_ctx->ctx.sregs.rflags, old_val);
	  if ((th_ctx->ctx.sregs.rflags & ERI_RFLAGS_ZERO_MASK) && updated)
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
  if (th_ctx->ext.op.code == _ERS_OP_SYSCALL) return syscall (th);
  (th_ctx->ext.op.code == _ERS_OP_SYNC_ASYNC ? sync_async : atomic) (th);
  return 0;
}
