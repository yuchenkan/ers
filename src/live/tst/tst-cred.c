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
  eri_info ("%u\n", tst_assert_syscall (getpid));
  eri_info ("%u\n", tst_assert_syscall (getppid));
  eri_info ("%u\n", tst_assert_syscall (getpgid, 0));
  eri_assert (tst_assert_syscall (getpgid, 0)
	== tst_assert_syscall (getpgid, tst_assert_syscall (getpid)));
  tst_assert_syscall (setpgid, 0, 0);
  eri_assert (tst_assert_syscall (getpgid, 0)
			== tst_assert_syscall (getpid));
  eri_assert (tst_assert_syscall (getpgid, 0)
			== tst_assert_syscall (getpgrp));
  tst_assert_sys_exit (0);
}
