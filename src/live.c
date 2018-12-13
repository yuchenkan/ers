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
  uint8_t __attribute__ ((aligned (16))) sigstack[ERI_LIVE_SIG_STACK_SIZE];

  ERI_LST_NODE_FIELDS (thread)
};

struct sigact
{
  int32_t lock;

  void *act;
  int32_t flags;
  struct eri_sigset mask;
};

struct internal
{
  struct eri_common *common;
  struct eri_mtpool *pool;

  int32_t sys_pid;
  struct eri_daemon *daemon;

  struct sigact sigacts[ERI_NSIG];

  int32_t threads_lock;
  ERI_LST_LIST_FIELDS (thread)
};

ERI_DEFINE_LIST (static, thread, struct internal, struct thread)

#define MT(internal)	(thread_lst_get_size (internal) > 1)

static struct eri_live_thread_entry *
alloc_thread_entry (struct thread *th)
{
  struct internal *internal = th->internal;

  struct eri_live_thread_entry *entry = eri_assert_cmalloc (MT (internal),
					&internal->pool, sizeof *entry);
  uint64_t stack_top = eri_assert_cmalloc (MT(internal), &internal->pool,
					   internal->common->stack_size);
  eri_live_init_thread_entry (entry, th, stack_top,
			      internal->common->stack_size, th->sigstack);
  return entry;
}

static struct thread *
alloc_thread (struct internal *internal, int32_t *clear_tid)
{
  struct thread *th = eri_assert_cmalloc (MT (internal),
					  &internal->pool, sizeof *th);

  th->internal = internal;
  th->entry = alloc_thread_entry (internal);

  th->alive = 1;
  th->clear_tid = clear_tid;

  eri_clock (mt, &internal->threads_lock);
  thread_lst_append (internal, th);
  eri_cunlock (mt, &internal->threads_lock);
  return th;
}

static void
start_thread (struct thread *th)
{
  struct internal *internal = th->internal;

  uint8_t mt = MT (internal);
  uint64_t file_buf_size = internal->common->file_buf_size;
  th->file_buf = eri_assert_cmalloc (mt, &internal->pool,
				     file_buf_size);
  th->file = eri_open_path (internal->path, "thread-", ERI_OPEN_WITHID,
			    th->id, th->file_buf, file_buf_size);

  th->sys_tid = ERI_ASSERT_SYSCALL_RES (gettid);

  struct eri_stack stack = { th->sigstack, 0, ERI_LIVE_SIG_STACK_SIZE };
  ERI_ASSERT_SYSCALL (sigaltstack, &stack, 0);

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_GS, th->entry);
}

void
eri_live_init (struct eri_common *common)
{
  struct eri_mtpool *pool = (void *) common->buf;
  eri_assert_init_pool (&pool->pool, common->buf + eri_size_of (*pool, 16),
			common->buf_size - eri_size_of (*pool, 16));

  struct internal *internal = eri_assert_malloc (&pool->pool,
						 sizeof *internal);

  internal->common = common;
  internal->pool = pool;

  internal->sys_pid = ERI_ASSERT_SYSCALL_RES (getpid);

  internal->daemon = eri_daemon_start (0, pool, 256 * 1024);

  ERI_LST_INIT_LIST (thread, internal);

  struct thread *th = alloc_thread (internal, 0);
  th->id = 0;

  start_thread (th);
}

uint8_t
eri_live_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
		  uint64_t a3, uint64_t a4, uint64_t a5,
		  struct eri_live_entry_syscall_info *info, void *thread)
{
#if 0
  int32_t nr = (int32_t) info->rax;
  if (nr == __NR_clone)
    {
    }
#endif
  return eri_live_do_syscall (a0, a1, a2, a3, a4, a5, info);
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
  return 0;
}

void
eri_live_atomic_load (uint64_t mem, uint64_t ver, uint64_t val, void *thread)
{
}

void
eri_live_atomic_stor (uint64_t mem, uint64_t ver, void *thread)
{
}

void
eri_live_atomic_load_stor (uint64_t mem, uint64_t ver, uint64_t val,
			   void *thread)
{
}
