#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  int32_t pipe[2];

  tst_assert_syscall (pipe, pipe);
  tst_check (pipe[0] + pipe[1]);
  tst_assert_syscall (close, pipe[0]);
  tst_assert_syscall (close, pipe[1]);

  tst_assert_syscall (pipe2, pipe, 0);
  tst_check (pipe[0] + pipe[1]);
  tst_assert_syscall (close, pipe[0]);
  tst_assert_syscall (close, pipe[1]);

  eri_assert (tst_syscall (pipe, 0) == ERI_EFAULT);

  int32_t *pipe1 = tst_assert_live_alloc_boundary (sizeof *pipe1, 4096);
  eri_assert (tst_syscall (pipe, pipe1) == ERI_EFAULT);
  tst_check (pipe1[0]);

  tst_assert_sys_exit (0);
}
