#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  tst_assert_syscall (setuid, tst_assert_syscall (getuid));
  tst_assert_syscall (setgid, tst_assert_syscall (getgid));
  eri_info ("%u\n", tst_assert_syscall (getppid));
  tst_assert_sys_exit (0);
}
