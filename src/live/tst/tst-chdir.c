#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  int32_t fd = tst_assert_syscall (open, ".",
				   ERI_O_RDONLY | ERI_O_DIRECTORY);
  tst_assert_syscall (chdir, "/proc/self");
  tst_assert_syscall (fchdir, fd);
  eri_assert (tst_syscall (chdir, "/proc/self/maps") == ERI_ENOTDIR);
  tst_assert_syscall (close, fd);
  tst_assert_sys_exit (0);
}
