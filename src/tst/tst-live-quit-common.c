#include <stdint.h>

#include "tst/tst-live-quit-common.h"

#include "live.h"
#include "live-entry.h"
#include "common.h"

#include "lib/rbtree.h"
#include "lib/lock.h"
#include "lib/printf.h"
#include "lib/syscall.h"
#include "lib/malloc.h"

int32_t tst_live_quit_printf_lock;

struct tst_thread
{
  int32_t tid;
  void *thread;

  ERI_RBT_NODE_FIELDS (tst_thread, struct tst_thread)
};

static struct tst_threads
{
  int32_t lock;
  ERI_RBT_TREE_FIELDS (tst_thread, struct tst_thread)
} threads;

ERI_DEFINE_RBTREE (static, tst_thread, struct tst_threads, struct tst_thread,
		   int32_t, eri_less_than)

static void *get_thread (void) __attribute__ ((unused));

static void *
get_thread (void)
{
  int32_t tid = (int32_t) ERI_ASSERT_SYSCALL_RES (gettid);
  eri_lock (&threads.lock);
  void *t = tst_thread_rbt_get (&threads, &tid, ERI_RBT_EQ)->thread;
  eri_unlock (&threads.lock);
  return t;
}

void
tst_live_quit_insert_thread (struct eri_live_thread_entry *entry)
{
  uint8_t *buf = (void *) (entry->top - entry->stack_size);
  struct eri_pool *pool = (void *) buf;
  eri_assert_init_pool (pool, buf + eri_size_of (*pool, 16),
			entry->stack_size - eri_size_of (*pool, 16));

  struct tst_thread *t = eri_assert_malloc (pool, sizeof *t);
  t->tid = (int32_t) ERI_ASSERT_SYSCALL_RES (gettid);
  eri_assert_lprintf (&tst_live_quit_printf_lock,
		      "insert thread %u\n", t->tid);
  t->thread = entry->thread;
  eri_lock (&threads.lock);
  tst_thread_rbt_insert (&threads, t);
  eri_unlock (&threads.lock);
}

static void *
remove_thread (void)
{
  int32_t tid = (int32_t) ERI_ASSERT_SYSCALL_RES (gettid);
  eri_lock (&threads.lock);
  struct tst_thread *t = tst_thread_rbt_get (&threads, &tid, ERI_RBT_EQ);
  tst_thread_rbt_remove (&threads, t);
  eri_unlock (&threads.lock);
  return t->thread;
}

void
eri_live_init_thread_entry (struct eri_live_thread_entry *entry,
		void *thread, uint64_t stack_top, uint64_t stack_size,
		void *sig_stack)
{
  entry->top = stack_top;
  entry->stack_size = stack_size;

  entry->thread = thread;
  *(struct eri_live_thread_entry **) sig_stack = entry;
}

void
tst_live_quit_block_signals (void)
{
  struct eri_sigset set;
  eri_sigfillset (&set);
#ifdef TST_LIVE_QUIT_GROUP
  eri_sigdelset (&set, ERI_SIGRTMIN);
#endif
  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK,
		      &set, 0, ERI_SIG_SETSIZE);
}

#ifdef TST_LIVE_QUIT_GROUP
void
eri_live_entry_sigaction (int32_t sig, struct eri_siginfo *info,
			  struct eri_ucontext *uctx)
{
  eri_assert (0);
}
#endif

void tst_live_quit_init (uint64_t rsp) __attribute__ ((noreturn));

void
tst_live_quit_init (uint64_t rsp)
{
  eri_assert_printf ("rsp = %lx\n", rsp);

#define BUF_SIZE (64 * 1024 * 1024)
  static struct eri_common common = {
    0, 4096, 0, BUF_SIZE, 1024 * 1024, 32 * 1024
  };
  common.buf = (uint64_t) ERI_ASSERT_SYSCALL_RES (
			mmap, 0, BUF_SIZE, ERI_PROT_READ | ERI_PROT_WRITE,
			ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);

  struct eri_rtld rtld = { 0, rsp - 8 };

  eri_live_init (&common, &rtld);
}

#ifdef TST_LIVE_QUIT_CLONE

void
tst_live_quit_clone (uint8_t *stack, int32_t *ptid, int32_t *ctid,
		     void (*fn) (void *), void *data)
{
  *(uint64_t *) stack = (uint64_t) fn;
  *(uint64_t *) (stack + 8) = (uint64_t) data;

  struct eri_live_entry_syscall_info info = { __NR_clone };
  int8_t done = 0;
  while (done != 1)
    {
      done = eri_live_syscall (ERI_SUPPORTED_CLONE_FLAGS,
			       (uint64_t) stack + TST_LIVE_QUIT_STACK_SIZE,
			       (uint64_t) ptid, (uint64_t) ctid, 0, 0,
			       &info, get_thread ());
      eri_assert_lprintf (&tst_live_quit_printf_lock, "done = %x\n", done);
    }
}

#endif

static void do_exit (int32_t nr, int32_t status) __attribute__ ((noreturn));

static void
do_exit (int32_t nr, int32_t status)
{
  struct eri_live_entry_syscall_info info = { nr };
  while (1)
    eri_assert (eri_live_syscall (status, 0, 0, 0, 0, 0, &info,
				  remove_thread ()) != 0);
}

void
tst_live_quit_exit (int32_t status)
{
  do_exit (__NR_exit, status);
}

void
tst_live_quit_exit_group (int32_t status)
{
  do_exit (__NR_exit_group, status);
}
