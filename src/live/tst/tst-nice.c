#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_assert (tst_syscall (getpriority, -1, 0) == ERI_EINVAL);

  int32_t pid = tst_assert_syscall (getpid);
  eri_info ("%lu\n", tst_assert_syscall (getpriority, ERI_PRIO_PROCESS, 0));
  eri_assert (tst_syscall (getpriority, ERI_PRIO_PROCESS, 0)
		== tst_syscall (getpriority, ERI_PRIO_PROCESS, pid));

  int32_t pgid = tst_assert_syscall (getpgrp);
  eri_info ("%lu\n", tst_assert_syscall (getpriority, ERI_PRIO_PGRP, 0));
  eri_assert (tst_syscall (getpriority, ERI_PRIO_PGRP, 0)
		== tst_syscall (getpriority, ERI_PRIO_PGRP, pgid));

  int32_t uid = tst_assert_syscall (getuid);
  eri_info ("%lu\n", tst_assert_syscall (getpriority, ERI_PRIO_USER, 0));
  eri_assert (tst_syscall (getpriority, ERI_PRIO_USER, 0)
		== tst_syscall (getpriority, ERI_PRIO_USER, uid));

  uint32_t nice = eri_max (
	tst_assert_syscall (getpriority, ERI_PRIO_PROCESS, 0) - 1, 1);
  tst_assert_syscall (setpriority, ERI_PRIO_PROCESS, pid, 20 - nice);
  eri_assert (tst_assert_syscall (getpriority,
				  ERI_PRIO_PROCESS, pid) == nice);
  eri_info ("%lu\n", nice);

  nice = tst_assert_syscall (getpriority, ERI_PRIO_PGRP, 0);
  tst_assert_syscall (setpriority, ERI_PRIO_PGRP, pgid, 20 - nice);
  eri_assert (tst_assert_syscall (getpriority,
				  ERI_PRIO_PGRP, pgid) == nice);
  eri_info ("%lu\n", nice);

  nice = tst_assert_syscall (getpriority, ERI_PRIO_USER, 0);
  tst_assert_syscall (setpriority, ERI_PRIO_USER, uid, 20 - nice);
  eri_assert (tst_assert_syscall (getpriority,
				  ERI_PRIO_USER, uid) == nice);
  eri_info ("%lu\n", nice);

  tst_assert_sys_exit (0);
}
