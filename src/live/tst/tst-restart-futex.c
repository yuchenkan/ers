/* vim: set ft=cpp: */

#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/util.h>

#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-restart-syscall.h>

#if 0
static int32_t pipe[2];

  char buf = 0xab;
  tst_assert_syscall (write, pipe[1], &buf, 1);

  tst_assert_syscall (pipe2, pipe, ERI_O_DIRECT);

  char buf;
  tst_assert_syscall (read, pipe[0], &buf, 1);
  eri_assert (buf == 0xab);

  tst_assert_syscall (close, pipe[0]);
  tst_assert_syscall (close, pipe[1]);
#endif

static int32_t futex;

TST_LIVE_RESTART_SYSCALL_DEFINE_TST (ERI_EMPTY, ERI_EVAL (do {
  tst_atomic_store (&futex, 1, 1);
  tst_assert_syscall (futex, &futex, ERI_FUTEX_WAKE_PRIVATE, 1);
} while (0)), ERI_EVAL (do {
  uint64_t res = tst_syscall (futex, &futex, ERI_FUTEX_WAIT_PRIVATE, 0, 0);
  eri_assert (eri_syscall_is_ok (res) || res  == ERI_EAGAIN);
} while (0)), ERI_EMPTY, 0, 0)
