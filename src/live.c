#include "common.h"
#include "live-entry.h"

#include "lib/list.h"
#include "lib/malloc.h"
#include "lib/atomic.h"
#include "lib/printf.h"

struct internal;

struct thread
{
  uint64_t id;
  struct internal *internal;

  struct eri_live_thread_entry *entry;

  int32_t alive;
  int32_t *clear_tid;

  uint8_t *file_buf;
  eri_file_t file;

  int32_t sys_tid;
  uint8_t __attribute__ ((aligned (16))) sig_stack[ERI_LIVE_SIG_STACK_SIZE];

  struct eri_stack user_sig_stack;

  ERI_LST_NODE_FIELDS (thread)
};

struct sig_action
{
  int32_t lock;

  uint8_t mask_all;
  struct eri_sigaction act;
};

struct internal
{
  struct eri_common *common;
  struct eri_mtpool *pool;

  int32_t sys_pid;

  struct sig_action sig_actions[ERI_NSIG - 1];

  uint64_t *atomic_mem_table;
  uint64_t atomic_mem_table_size;

  struct eri_daemon *daemon;

  uint8_t quitting;
  int32_t quit_lock;

  uint32_t live_count;
  uint32_t multi_threading;

  uint64_t thread_id;
  int32_t threads_lock;
  ERI_LST_LIST_FIELDS (thread)
};

ERI_DEFINE_LIST (static, thread, struct internal, struct thread)

static void
daemon_sig_action (int32_t sig, struct eri_siginfo *info,
		   struct eri_ucontext *ctx)
{
  eri_assert (sig == ERI_SIGSEGV);
  extern uint8_t segv_quit_thread_clear_tid[];
  extern uint8_t segv_quit_thread_skip_clear_tid[];
  if (info->code > 0 && ctx->mctx.rip == (uint64_t) segv_quit_thread_clear_tid)
    /* XXX: add a warning.  */
    ctx->mctx.rip = (uint64_t) segv_quit_thread_skip_clear_tid;
  else eri_assert (0);
}

static void
init_daemon (void *lock)
{
  struct eri_sigset set;
  eri_sigfillset (&set);
  eri_sigdelset (&set, ERI_SIGSEGV);
  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK, &set,
		      0, ERI_SIG_SETSIZE);

  struct eri_sigaction act = {
    daemon_sig_action, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
  };
  eri_sigfillset (&act.mask);
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGSEGV, &act, 0, ERI_SIG_SETSIZE);

  eri_unlock (lock);
}

static struct eri_live_thread_entry *
alloc_thread_entry (uint8_t mt, struct thread *th)
{
  struct internal *internal = th->internal;

  struct eri_live_thread_entry *entry = eri_assert_cmalloc (
		mt, internal->pool, ERI_LIVE_THREAD_ENTRY_SIZE);

  uint64_t stack_size = internal->common->stack_size;
  uint64_t stack_top = (uint64_t) eri_assert_cmalloc (
		mt, internal->pool, stack_size) + stack_size;

  eri_live_init_thread_entry (entry, th, stack_top, stack_size,
			      th->sig_stack);
  return entry;
}

static void
free_thread_entry (uint8_t mt, struct eri_live_thread_entry *entry)
{
  struct internal *internal = ((struct thread *) entry->thread)->internal;
  eri_assert_cfree (mt, internal->pool,
		    (void *) (entry->top - entry->stack_size));
  eri_assert_cfree (mt, internal->pool, entry);
}

static struct thread *
alloc_thread (uint8_t mt, struct internal *internal, int32_t *clear_tid)
{
  struct thread *th = eri_assert_cmalloc (mt, internal->pool, sizeof *th);

  th->internal = internal;
  th->entry = alloc_thread_entry (mt, th);

  th->alive = 1;
  th->clear_tid = clear_tid;
  return th;
}

static void
free_thread (uint8_t mt, struct thread *th)
{
  struct internal *internal = th->internal;
  free_thread_entry (mt, th->entry);
  eri_assert_cfree (mt, internal->pool, th);
}

static void
append_thread (uint8_t mt, struct thread *th)
{
  struct internal *internal = th->internal;
  eri_clock (mt, &internal->threads_lock);
  thread_lst_append (internal, th);
  eri_cunlock (mt, &internal->threads_lock);
}

static void
remove_thread (uint8_t mt, struct thread *th)
{
  struct internal *internal = th->internal;
  eri_clock (mt, &internal->threads_lock);
  thread_lst_remove (internal, th);
  eri_cunlock (mt, &internal->threads_lock);
}

static void
start_thread (uint8_t mt, struct thread *th)
{
  struct internal *internal = th->internal;
  uint64_t file_buf_size = internal->common->file_buf_size;
  th->file_buf = eri_assert_cmalloc (mt, internal->pool,
				     file_buf_size);
#if 0
  th->file = eri_open_path (internal->path, "thread-", ERI_OPEN_WITHID,
			    th->id, th->file_buf, file_buf_size);
#endif

  th->user_sig_stack.size = 0;
}

static void
stop_thread (uint8_t mt, struct thread *th)
{
  struct internal *internal = th->internal;

  /* See below.  */
  if (! th->file_buf) return;

#if 0
  eri_assert_fclose (th->file);
#endif
  eri_assert_cfree (mt, internal->pool, th->file_buf);

  /*
   * Mark the thread stopped. This is required because stop_thread in
   * non group exit is called before hold_quit, so if hold_quit failed,
   * there will be another try to stop_thread.
  */
  th->file_buf = 0;
}

void
eri_live_init (struct eri_common *common, struct eri_rtld *rtld)
{
  uint64_t atomic_mem_table_size = 2 * 1024 * 1024;

  ERI_ASSERT_SYSCALL (mprotect, common->buf, common->buf_size,
		      ERI_PROT_READ | ERI_PROT_WRITE);

  struct eri_mtpool *pool = (void *) common->buf;
  eri_assert_init_pool (&pool->pool,
			(void *) common->buf + eri_size_of (*pool, 16),
			common->buf_size - eri_size_of (*pool, 16));

  struct internal *internal = eri_assert_malloc (&pool->pool,
						 sizeof *internal);

  internal->common = common;
  internal->pool = pool;

  internal->sys_pid = ERI_ASSERT_SYSCALL_RES (getpid);

  int32_t sig;
  for (sig = 1; sig < ERI_NSIG; ++sig)
    {
      if (sig == ERI_SIGSTOP || sig == ERI_SIGKILL) continue;

      struct sig_action *action = &internal->sig_actions[sig - 1];
      action->lock = 0;

      ERI_ASSERT_SYSCALL (rt_sigaction, sig, 0,
			  &action->act, ERI_SIG_SETSIZE);
      action->mask_all = eri_sigset_full (&action->act.mask);

      struct eri_sigaction new = {
	eri_live_entry_sig_action,
	ERI_SA_RESTORER | ERI_SA_SIGINFO | ERI_SA_ONSTACK,
	0
      };
      eri_sigfillset (&new.mask);

      ERI_ASSERT_SYSCALL (rt_sigaction, sig, &new, 0, ERI_SIG_SETSIZE);
    }

  internal->atomic_mem_table = eri_assert_malloc (&pool->pool,
	atomic_mem_table_size * sizeof internal->atomic_mem_table[0]);
  internal->atomic_mem_table_size = atomic_mem_table_size;

  internal->daemon = eri_daemon_start (0, pool, 256 * 1024);
  int32_t init_daemon_lock = 1;
  eri_daemon_invoke (internal->daemon, init_daemon, &init_daemon_lock);

  internal->live_count = 1;
  internal->multi_threading = 0;

  internal->thread_id = 0;
  internal->threads_lock = 0;
  ERI_LST_INIT_LIST (thread, internal);

  struct thread *th = alloc_thread (1, internal, 0);
  th->id = 0;

  append_thread (0, th);

  ERI_ASSERT_SYSCALL (set_tid_address, &th->alive);
  th->sys_tid = ERI_ASSERT_SYSCALL_RES (gettid);
  start_thread (1, th);

  eri_lock (&init_daemon_lock);

  eri_live_entry_start (th->entry, rtld);
}

static uint8_t
try_hold_quit (uint8_t mt, int32_t *lock)
{
  uint8_t hold = eri_catomic_inc_fetch (mt, lock) > 0;
  eri_barrier ();
  if (! hold) eri_catomic_dec (mt, lock);
  return hold;
}

static void
unhold_quit (uint8_t mt, int32_t *lock)
{
  eri_barrier ();
  eri_catomic_dec (mt, lock);
}

static uint8_t
try_quit (uint8_t mt, struct internal *internal)
{
  if (! mt) return 1;

  if (eri_atomic_exchange (&internal->quitting, 1) == 1) return 0;
  eri_barrier ();

  while (! eri_atomic_compare_exchange (&internal->quit_lock, 0, -2147483647))
    ERI_ASSERT_SYSCALL (sched_yield);
  eri_barrier ();
  return 1;
}

uint64_t eri_live_atomic_hash_mem (uint64_t mem, void *thread);
void eri_live_atomic_store (uint64_t mem, uint64_t ver, void *thread);

static void
quit_thread (void *thread)
{
  struct thread *th = thread;
  eri_lock (&th->alive);

  struct internal *internal = th->internal;
  int32_t *clear_tid = th->clear_tid;

  if (clear_tid)
    {
      uint64_t idx = eri_live_atomic_hash_mem ((uint64_t) clear_tid, th);

      uint8_t segv = 0;
      uint64_t ver;

      uint32_t i = 0;
      while (eri_atomic_bit_test_set (internal->atomic_mem_table + idx, 0))
	if (++i % 16 == 0) ERI_ASSERT_SYSCALL (sched_yield);

      eri_barrier ();

      asm ("segv_quit_thread_clear_tid:\n"
	   "  movl\t$0, %0\n"
	   "  jmp\t1f\n"
	   "segv_quit_thread_skip_clear_tid:\n"
	   "  movb\t$1, %b1\n"
	   "1:" : "=m" (*clear_tid), "=r" (segv));

      if (! segv)
	{
	  ver = internal->atomic_mem_table[idx] >> 1;
	  internal->atomic_mem_table[idx] += 2;
	}

      eri_barrier ();
      eri_atomic_and (internal->atomic_mem_table + idx, -2);

      if (! segv) eri_live_atomic_store ((uint64_t) clear_tid, ver, th);

      ERI_ASSERT_SYSCALL (futex, clear_tid, ERI_FUTEX_WAKE, 1);
    }

  free_thread (1, th);
  eri_barrier ();
  eri_atomic_dec (&internal->multi_threading);
}

void eri_live_quit (int32_t *alive) __attribute__ ((noreturn));

static void
sig_quit_thread (int32_t sig, struct eri_siginfo *info,
		  struct eri_ucontext *ctx, void *thread)
{
  struct thread *th = thread;
  struct internal *internal = th->internal;

  stop_thread (1, th);
  remove_thread (1, th);

  th->clear_tid = 0;
  eri_daemon_invoke (internal->daemon, quit_thread, th);
  eri_live_quit (&th->alive);
}

static void
inform_quit (void *thread)
{
  struct thread *th = thread;
  struct internal *internal = th->internal;

  struct thread *t;
  ERI_LST_FOREACH (thread, internal, t)
    if (t != th)
      ERI_ASSERT_SYSCALL (tgkill, internal->sys_pid,
			  t->sys_tid, ERI_SIGRTMIN);
}

static uint8_t
final_quit (uint8_t mt, struct thread *th, uint8_t group)
{
  struct internal *internal = th->internal;

  if (group)
    {
      if (! try_quit (mt, internal)) return 0;
      eri_daemon_invoke (internal->daemon, inform_quit, th);
    }

  stop_thread (1, th);
  remove_thread (1, th);

  while (mt)
    {
      ERI_ASSERT_SYSCALL (sched_yield);
      mt = !! eri_atomic_load (&internal->multi_threading);
    }
  eri_barrier ();

  eri_daemon_stop (0, internal->daemon);

  /*
   * As there should be no one else allocating memory, freeing the stack
   * still in use is safe here.
   */
  free_thread (0, th);
  struct eri_pool *pool = &internal->pool->pool;
  eri_assert_free (pool, internal->atomic_mem_table);
  eri_assert_free (pool, internal);
  eri_assert (pool->used == 0);

  return 1;
}

#ifndef ERI_NO_TST
void tst_live_sig_final_quit (int32_t sig, struct eri_siginfo *info,
			      struct eri_ucontext *ctx);
#endif

static void
sig_final_quit (int32_t sig, struct eri_siginfo *info,
		struct eri_ucontext *ctx, void *thread)
{
  struct thread *th = thread;
  struct internal *internal = th->internal;
  uint8_t mt = eri_atomic_load (&internal->multi_threading);

  int32_t pid = internal->sys_pid;
  int32_t tid = th->sys_tid;

  if (! final_quit (mt, th, 1)) sig_quit_thread (sig, info, ctx, th);

  struct eri_sigaction act = {
#ifdef ERI_NO_TST
    ERI_SIG_DFL
#else
    tst_live_sig_final_quit, ERI_SA_RESTORER, 0
#endif
  };
  ERI_ASSERT_SYSCALL (rt_sigaction, sig, &act, 0, ERI_SIG_SETSIZE);

  ERI_ASSERT_SYSCALL (tgkill, pid, tid, sig);

  struct eri_sigset set;
  eri_sigfillset (&set);
  eri_sigdelset (&set, sig);
  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK, &set, 0,
		      ERI_SIG_SETSIZE);
}

static void
sig_term (int32_t sig, struct eri_siginfo *info,
	  struct eri_ucontext *ctx, void *thread)
{
  sig_final_quit (sig, info, ctx, thread);
}

static void
sig_core (int32_t sig, struct eri_siginfo *info,
	  struct eri_ucontext *ctx, void *thread)
{
  sig_final_quit (sig, info, ctx, thread);
}

static void
sig_stop (int32_t sig, struct eri_siginfo *info,
	  struct eri_ucontext *ctx, void *thread)
{
  struct thread *th = thread;
  struct internal *internal = th->internal;
  ERI_ASSERT_SYSCALL (kill, internal->sys_pid, ERI_SIGSTOP);
}

void
eri_live_get_sig_action (int32_t sig, struct eri_siginfo *info,
			 struct eri_ucontext *ctx, int32_t intr,
			 struct eri_live_entry_sig_action_info *act_info,
			 void *thread)
{
  eri_assert (act_info->type == ERI_LIVE_ENTRY_SIG_ACTION_UNKNOWN);

  struct thread *th = thread;
  struct internal *internal = th->internal;
  uint8_t mt = !! eri_atomic_load (&internal->multi_threading);
  if (mt && eri_atomic_load (&internal->quitting))
    {
      act_info->type = ERI_LIVE_ENTRY_SIG_ACTION_INTERNAL;
      act_info->act = (uint64_t) sig_quit_thread;
      return;
    }

  struct sig_action *action = &internal->sig_actions[sig - 1];

  struct eri_sigaction act;

  eri_clock (mt, &action->lock);
  uint8_t mask_all = action->mask_all;
  act = action->act;
  if (act.act != ERI_SIG_DFL && act.act != ERI_SIG_IGN
      && (act.flags & ERI_SA_RESETHAND))
    action->act.act = ERI_SIG_DFL;
  eri_cunlock (mt, &action->lock);

  if ((act.act == ERI_SIG_DFL
       && (sig == ERI_SIGCHLD || sig == ERI_SIGCONT
	   || sig == ERI_SIGURG || sig == ERI_SIGWINCH))
      || act.act == ERI_SIG_IGN)
    {
      act_info->type = ERI_LIVE_ENTRY_SIG_NO_ACTION;
      if (intr != -1)
	{
	  /* TODO: Fix context to restart.  */
	}
      return;
    }

  if (act.act == ERI_SIG_DFL)
    {
      act_info->type = ERI_LIVE_ENTRY_SIG_ACTION_INTERNAL;
      if (sig == ERI_SIGHUP || sig == ERI_SIGINT || sig == ERI_SIGKILL
	  || sig == ERI_SIGPIPE || sig == ERI_SIGALRM || sig == ERI_SIGTERM
	  || sig == ERI_SIGUSR1 || sig == ERI_SIGUSR2 || sig == ERI_SIGIO
	  || sig == ERI_SIGPROF || sig == ERI_SIGVTALRM
	  || sig == ERI_SIGSTKFLT || sig == ERI_SIGPWR
	  || (sig >= ERI_SIGRTMIN && sig <= ERI_SIGRTMAX))
	act_info->act = (uint64_t) sig_term;
      else if (sig == ERI_SIGQUIT || sig == ERI_SIGILL || sig == ERI_SIGABRT
	       || sig == ERI_SIGFPE || sig == ERI_SIGSEGV || sig == ERI_SIGBUS
	       || sig == ERI_SIGSYS || sig == ERI_SIGTRAP
	       || sig == ERI_SIGXCPU || sig == ERI_SIGXFSZ)
	act_info->act = (uint64_t) sig_core;
      else if (sig == ERI_SIGTSTP || sig == ERI_SIGTTIN || sig == ERI_SIGTTOU)
	act_info->act = (uint64_t) sig_stop;
      else eri_assert (0);
      return;
    }

  /* XXX */
  if ((intr == __NR_read || intr == __NR_readv
       || intr == __NR_write || intr == __NR_writev
       || intr == __NR_ioctl || intr == __NR_open
       || intr == __NR_wait4 || intr == __NR_waitid

       /* TODO: Check timeout. */
       || intr == __NR_accept || intr == __NR_accept4 || intr == __NR_connect
       || intr == __NR_recvfrom || intr == __NR_recvmsg
       || intr == __NR_recvmmsg
       || intr == __NR_sendto || intr == __NR_sendmsg
       || intr == __NR_sendmmsg

       || intr == __NR_flock
       /* TODO: Check operation. */
       || intr == __NR_fcntl
       || intr == __NR_mq_timedsend || intr == __NR_mq_timedreceive
       || intr == __NR_futex
       || intr == __NR_getrandom)
      && (act.flags & ERI_SA_RESTART)
      && ! (act_info->type & ERI_LIVE_ENTRY_SIG_ACTION_INTERNAL))
    {
      act_info->type |= ERI_LIVE_ENTRY_SIG_ACTION_RESTART;
      /* TODO: Fix context to restart.  */
    }
  else act_info->type = ERI_LIVE_ENTRY_SIG_ACTION;

  if (act.flags & ERI_SA_ONSTACK)
    act_info->type |= ERI_LIVE_ENTRY_SIG_ACTION_ON_STACK;

  act_info->act = (uint64_t) act.act;
  act_info->restorer = (uint64_t) act.restorer;

  /* XXX: SA_NODEFER */
  act_info->mask.mask_all = mask_all;
  act_info->mask.mask = act.mask;
}

uint64_t
eri_live_get_sig_stack (struct eri_live_entry_sig_stack_info *info,
			void *thread)
{
  /* TODO: Fix stack sp.  */
#if 0
  uint8_t switch_stack = stack.size
			 && ! (ctx->mctx.rsp > stack.sp
			       && ctx->mctx.rsp - stack.sp <= stack.size);
#endif
  return 0;
}

void
eri_live_start_thread (void *thread)
{
  struct thread *th = thread;
  struct internal *internal = th->internal;

  th->sys_tid = ERI_ASSERT_SYSCALL_RES (gettid);
  unhold_quit (1, &internal->quit_lock);

  start_thread (1, th);
}

int8_t
eri_live_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
		  uint64_t a3, uint64_t a4, uint64_t a5,
		  uint64_t *rax, void *thread)
{
  struct thread *th = thread;
  struct internal *internal = th->internal;
  uint8_t mt = !! eri_atomic_load (&internal->multi_threading);
  eri_barrier ();

  int32_t nr = *rax;
  if (nr == __NR_clone)
    {
      int32_t flags = a0;
      uint64_t user_child_stack = a1;
      int32_t *ptid = (void *) a2;
      int32_t *ctid = (void *) a3;
      void *newtls = (void *) a4;

      eri_assert (flags == ERI_SUPPORTED_CLONE_FLAGS);

      struct thread *child_th = alloc_thread (mt, internal, ctid);
      child_th->id = eri_catomic_inc_fetch (mt, &internal->thread_id);

      struct eri_live_entry_clone_info info = {
	flags, user_child_stack, ptid, &child_th->alive, newtls
      };

      if (! try_hold_quit (mt, &internal->quit_lock))
	{
	  free_thread (mt, child_th);
	  return -1;
	}
      append_thread (mt, child_th);
      eri_catomic_inc (mt, &internal->live_count);
      eri_catomic_inc (mt, &internal->multi_threading);
      eri_barrier ();

      uint8_t done = eri_live_entry_clone (th->entry, child_th->entry,
					   &info, rax);

      if (! done || ERI_SYSCALL_IS_ERROR (*rax))
	{
	  eri_barrier ();
	  eri_catomic_dec (mt, &internal->multi_threading);
	  eri_catomic_dec (mt, &internal->live_count);
	  remove_thread (mt, child_th);
	  unhold_quit (mt, &internal->quit_lock);

	  free_thread (mt, child_th);
	}
      return done;
    }
  else if (nr == __NR_exit || nr == __NR_exit_group)
    {
      if (nr == __NR_exit
	  && eri_catomic_dec_fetch (mt, &internal->live_count))
	{
	  eri_barrier ();
	  stop_thread (1, th);

	  if (! try_hold_quit (1, &internal->quit_lock))
	    {
	      eri_catomic_inc (mt, &internal->live_count);
	      return -1;
	    }

	  remove_thread (1, th);
	  unhold_quit (1, &internal->quit_lock);

	  eri_daemon_invoke (internal->daemon, quit_thread, th);
	}
      else if (! final_quit (mt, th, nr == __NR_exit_group))
	return -1;

      /* XXX: quit even if we are to restart in the sigaction.  */
      ERI_ASSERT_SYSCALL_NCS (nr, a0);
      __builtin_unreachable ();
    }
#if 0
  else if (nr == __NR_rt_sigaction)
    {
      if (! eri_live_entry_mark_complete (th->entry)) return 0;

      int32_t sig = a0;
      struct eri_sigaction *act = (void *) a1;
      struct eri_sigaction *old_act = (void *) a2;
      if (sig == 0 || sig >= ERI_SIGRTMAX)
	*rax = -ERI_EINVAL;
      else
	{
	}

      return 1;
    }
#endif
  else
    return eri_live_entry_do_syscall (a0, a1, a2, a3, a4, a5, rax,
				      th->entry);
}

#ifndef ERI_NO_TST

uint8_t
eri_tst_live_multi_threading (void *thread)
{
  struct thread *th = thread;
  return !! eri_atomic_load (&th->internal->multi_threading);
}

#endif

void
eri_live_sync_async (uint64_t cnt, void *thread)
{
}

void
eri_live_restart_sync_async (uint64_t cnt, void *thread)
{
}

uint64_t
eri_live_atomic_hash_mem (uint64_t mem, void *thread)
{
  uint64_t x = mem & ~0xf;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9;
  x = (x ^ (x >> 27)) * 0x94d049bb133111eb;
  x = x ^ (x >> 31);

  struct thread *th = thread;
  return x % th->internal->atomic_mem_table_size;
}

void
eri_live_atomic_load (uint64_t mem, uint64_t ver, uint64_t val, void *thread)
{
}

/* Pre-incremented version.  */
void
eri_live_atomic_store (uint64_t mem, uint64_t ver, void *thread)
{
}

void
eri_live_atomic_load_store (uint64_t mem, uint64_t ver, uint64_t val,
			   void *thread)
{
}
