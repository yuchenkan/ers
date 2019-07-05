#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  int32_t fd = tst_assert_syscall (open, "tst-chmod.t",
				   ERI_O_RDONLY | ERI_O_CREAT);
  tst_assert_syscall (fchmod, fd, ERI_S_IRUSR);
  tst_assert_syscall (close, fd);

  tst_assert_syscall (chmod, "tst-chmod.t", ERI_S_IRUSR);
  eri_assert (tst_syscall (chmod, 0, 0) == ERI_EFAULT);

  tst_assert_sys_exit (0);
}
