#ifndef TST_LIVE_TST_TST_SYSCALL_H
#define TST_LIVE_TST_TST_SYSCALL_H

#include <tst/tst-syscall.h>

#define tst_yield(n) \
  do {									\
    typeof (n) _i;							\
    typeof (n) _n = n;							\
    for (_i = 0; _i < _n; ++_i) tst_assert_syscall (sched_yield);	\
  } while (0)


/* ~(SIGKILL_MASK | SIGSTOP_MASK) */
#define TST_SIGSET_MASK			0xfffffffffffbfeff

#define tst_assert_sys_raise(sig) \
  tst_assert_syscall (tgkill, tst_assert_syscall (getpid),		\
		      tst_assert_syscall (gettid), sig)

#ifndef __ASSEMBLER__

struct tst_live_clone_args
{
  uint8_t *top;
  uint32_t delay;

  void (*fn) (void *);
  void *args;

  int32_t alive;
};

void tst_assert_live_clone (struct tst_live_clone_args *args);

struct tst_live_clone_raise_args
{
  struct tst_live_clone_args args;

  int32_t sig;
  int32_t pid, tid;
  uint32_t count;
};

void tst_assert_live_clone_raise (struct tst_live_clone_raise_args *args);
void tst_assert_live_clone_exit_group (struct tst_live_clone_args *args);

void *tst_assert_live_alloc_boundary (uint64_t size, uint64_t page_size);
void tst_assert_live_free_boundary (void *ptr, uint64_t page_size);

#endif

#endif
