#include "common.h"
#include "live-entry.h"

#include "lib/list.h"
#include "lib/malloc.h"

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

  void *act;
  int32_t flags;
  struct eri_sigmask mask;
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

  uint32_t multi_threading;

  uint64_t thread_id;
  int32_t threads_lock;
  ERI_LST_LIST_FIELDS (thread)
};

ERI_DEFINE_LIST (static, thread, struct internal, struct thread)

static struct eri_live_thread_entry *
alloc_thread_entry (uint8_t mt, struct thread *th)
{
  struct internal *internal = th->internal;

  struct eri_live_thread_entry *entry = eri_assert_cmalloc (
		mt, &internal->pool, ERI_LIVE_THREAD_ENTRY_SIZE);

  uint64_t stack_size = internal->common->stack_size
  uint64_t stack_top = (uint64_t) eri_assert_cmalloc (
		mt, &internal->pool, stack_size) + stack_size;

  eri_live_init_thread_entry (entry, th, stack_top, stack_size,
			      th->sig_stack);
  return entry;
}

static void
free_thread_entry (uint8_t mt, struct eri_live_thread_entry *entry)
{
  struct internal *internal = ((struct thread *) entry->thread)->internal;
  eri_assert_cfree (mt, &internal->pool, (void *) (th->top - th->stack_size));
  eri_assert_cfree (mt, &internal->pool, entry);
}

static struct thread *
alloc_thread (uint8_t mt, struct internal *internal, int32_t *clear_tid)
{
  struct thread *th = eri_assert_cmalloc (mt, &internal->pool, sizeof *th);

  th->internal = internal;
  th->entry = alloc_thread_entry (mt, internal);

  th->alive = 1;
  th->clear_tid = clear_tid;
  return th;
}

static void
free_thread (uint8_t mt, struct thread *th)
{
  struct internal *internal = th->internal;
  free_thread_entry (mt, th->entry);
  eri_assert_cfree (mt, &internal->pool, th);
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
  th->file_buf = eri_assert_cmalloc (mt, &internal->pool,
				     file_buf_size);
  th->file = eri_open_path (internal->path, "thread-", ERI_OPEN_WITHID,
			    th->id, th->file_buf, file_buf_size);

  th->sys_tid = ERI_ASSERT_SYSCALL_RES (gettid);

  th->user_sig_stack.size = 0;
}

static void
stop_thread (uint8_t mt, struct thread *th)
{
  struct internal *internal = th->internal;
  eri_assert_fclose (th->file);
  eri_assert_cfree (mt, &internal->pool, th->file_buf);

  /* Mark the thread stopped. This is required because stop_thread in
     non group exit is called before hold_quit, so if hold_quit failed,
     there will be another try to stop_thread.
  */
  th->file_buf = 0;
}

static void
set_sigmask (struct eri_sigmask *mask, const struct eri_sigset *set)
{
  mask->mask_all = eri_sigset_full (set);
  mask->mask = *set;
}

void
eri_live_init (struct eri_common *common, struct eri_rtld *rtld)
{
  uint64_t atomic_mem_table_size = 2 * 1024 * 1024;

  struct eri_mtpool *pool = (void *) common->buf;
  eri_assert_init_pool (&pool->pool, common->buf + eri_size_of (*pool, 16),
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

      internal->sig_actions[sig - 1].lock = 0;

      struct eri_sigaction old;
      ERI_ASSERT_SYSCALL (rt_sigaction, sig, 0, &old, ERI_SIG_SETSIZE);

      internal->sig_actions[sig - 1].act = old.act;
      internal->sig_actions[sig - 1].flags = old.flags;
      set_sigmask (&internal->sig_actions[sig - 1].mask, &old.mask);

      struct eri_sigaction new = {
	eri_live_entry_sigaction,
	ERI_SA_RESTORER | ERI_SA_SIGINFO | ERI_SA_ONSTACK
	  | (old.flags & ERI_SA_RESTART),
	old.act == ERI_SIG_DFL || old.act == ERI_SIG_IGN
	  ? eri_sigreturn : old.restorer;
      };
      eri_sigfillset (&new.mask);

      ERI_ASSERT_SYSCALL (rt_sigaction, sig, &new, 0, ERI_SIG_SETSIZE);
    }

  internal->atomic_mem_table = eri_assert_malloc (&pool->pool,
	atomic_mem_table_size * sizeof internal->atomic_mem_table[0]);
  internal->atomic_mem_table_size = atomic_mem_table_size;

  internal->daemon = eri_daemon_start (0, pool, 256 * 1024);

  internal->multi_threading = 0;

  internal->thread_id = 0;
  internal->threads_lock = 0;
  ERI_LST_INIT_LIST (thread, internal);

  struct thread *th = alloc_thread (internal, 0);
  th->id = 0;

  start_thread (0, th);

  eri_live_entry_start (th->entry, rtld);
}

static uint8_t
try_hold_quit (uint8_t mt, int32_t *lock)
{
  return eri_catomic_inc_fetch (mt, lock) > 0;
}

static void
unhold_quit (uint8_t mt, int32_t *lock)
{
  eri_catomic_dec (mt, lock);
}

static uint8_t
try_quit (uint8_t mt, struct internal *internal)
{
  if (! mt) return 1;

  if (eri_atomic_exchange (&internal->quitting, 1) == 1) return 0;

  while (! eri_atomic_compare_exchange (&internal->quit_lock, 0, -2147483647))
    ERI_ASSERT_SYSCALL (sched_yield);
}

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
      uint32_t i = 0;

      while (eri_atomic_bit_test_set (internal->atomic_mem_table + idx, 0))
	if (++i % 16 == 0) ERI_ASSERT_SYSCALL (sched_yield);

      /* XXX: handle sigsegv.  */
      *clear_tid = 0;
      uint64_t ver = internal->atomic_mem_table[idx] >> 1;
      internal->atomic_mem_table[idx] += 2;

      eri_atomic_and (internal->atomic_mem_table + idx, -2);

      eri_live_atomic_stor ((uint64_t) clear_tid, ver, th);

      ERI_ASSERT_SYSCALL (futex, clear_tid, ERI_FUTEX_WAKE, 1);
    }

  free_thread (1, th);
  eri_atomic_dec (&internal->multi_threading);
}

void eri_live_quit (int32_t *alive) __attribute__ ((noreturn));

void
eri_live_start_sigaction (int32_t sig, struct eri_stack *stack,
		struct eri_live_entry_sigaction_info *info, void *thread)
{
  struct thread *th = thread;
  struct internal *internal = th->internal;
  if (eri_atomic_load (&internal->quitting))
    {
      stop_thread (1, th);
      remove_thread (1, th);

      th->clear_tid = 0;
      eri_daemon_invoke (intenral->daemon, quit_thread, th);
      eri_live_quit (&th->alive);
    }

  struct eri_ucontext *ctx = (void *) info->rdx;
  /* TODO fix stack sp */
}

static void
clone_start_thread (struct eri_live_entry_syscall_info *info, void *thread)
{
  struct thread *th = thread;
  struct internal *internal = th->internal;
  unhold_quit (1, &internal->quit_lock);

  start_thread (1, th);
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

int8_t
eri_live_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
		  uint64_t a3, uint64_t a4, uint64_t a5,
		  struct eri_live_entry_syscall_info *info, void *thread)
{
  struct thread *th = thread;
  struct internal *internal = th->internal;
  uint8_t mt = !! eri_atomic_load (&internal->multi_threading);

  int32_t nr = (int32_t) info->rax;
  if (nr == __NR_clone)
    {
      int32_t flags = (int32_t) a0;
      uint64_t user_child_stack = a1;
      int32_t *ptid = (void *) a2;
      int32_t *ctid = (void *) a3;
      void *newtls = (void *) a4;

      eri_assert (flags == ERI_SUPPORTED_CLONE_FLAGS);

      struct thread *child_th = alloc_thread (internal, ctid);
      child_th->id = eri_catomic_inc_fetch (mt, &internal->thread_id);

      struct eri_live_entry_clone_info clone_info = {
	flags, user_child_stack, ptid, &child_th->alive, newtls,
	clone_start_thread
      };

      if (! try_hold_quit (mt, &internal->quit_lock))
	{
	  free_thread (mt, child_th);
	  return -1;
	}
      append_thread (mt, child_th);
      eri_catomic_inc (mt, &internal->multi_threading);

      uint8_t done = eri_live_entry_clone (th->entry, child_th->entry,
					   &clone_info, info);

      if (ERI_SYSCALL_IS_ERROR (info->rax))
	{
	  eri_catomic_dec (mt, &internal->multi_threading);
	  remove_thread (mt, child_th);
	  unhold_quit (mt, &internal->quit_lock);

	  free_thread (mt, child_th);
	}
      return done;
    }
  else if (nr == __NR_exit || nr == __NR_exit_group)
    {
      int8_t group = (nr == __NR_exit && thread->id == 0)
		     || nr == __NR_exit_group;
      if (nr == __NR_exit && th->id != 0)
	{
	  stop_thread (1, th);

	  if (! try_hold_quit (1, &internal->quit_lock)) return -1;
	  remove_thread (1, th);
	  unhold_quit (1, &internal->quit_lock);

	  eri_daemon_invoke (intenral->daemon, quit_thread, th);
	}
      else
	{
	  if (! try_quit (mt, internal)) return -1;

	  eri_daemon_invoke (inform_quit, th);

	  stop_thread (mt, th);
	  remove_thread (mt, th);

	  while (mt)
	    {
	      ERI_ASSERT_SYSCALL (sched_yield);
	      mt = !! eri_atomic_load (&internal->multi_threading);
	    }

	  eri_daemon_stop (0, internal->daemon);

	  /* As there should be no one else allocate memory, freeing
	     the stack still in use is safe.
	  */
	  free_thread (0, th);
          struct eri_mtpool *pool = internal->pool;
	  eri_assert_free (&pool->pool, internal);
	  eri_assert (pool->pool.used == 0);
	}

      /* XXX: quit even if we are to restart in the sigaction.  */
      ERI_ASSERT_SYSCALL (nr, a0);
    }
  else
    return eri_live_entry_do_syscall (a0, a1, a2, a3, a4, a5, info,
				      th->entry);
}

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
eri_live_atomic_stor (uint64_t mem, uint64_t ver, void *thread)
{
}

void
eri_live_atomic_load_stor (uint64_t mem, uint64_t ver, uint64_t val,
			   void *thread)
{
}
