/* vim: set ft=cpp: */

#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/util.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-restart-syscall.h>

static int32_t pipe[2];

TST_LIVE_RESTART_SYSCALL_DEFINE_TST (ERI_EVAL (do {
  tst_assert_syscall (pipe2, pipe, ERI_O_DIRECT);
} while (0)), ERI_EVAL (do {
  uint8_t buf;
  tst_assert_syscall (read, pipe[0], &buf, 1);
  eri_assert (buf == (uint8_t) 0xab);
} while (0)), ERI_EVAL (do {
  uint8_t buf = 0xab;
  tst_assert_syscall (write, pipe[1], &buf, 1);
} while (0)), ERI_EVAL (do {
  tst_assert_syscall (close, pipe[0]);
  tst_assert_syscall (close, pipe[1]);
} while (0)), 0, 0)
