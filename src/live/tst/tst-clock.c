#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  uint64_t t[2];
  eri_assert (tst_syscall (time, 1) == ERI_EFAULT);
  eri_info ("time: %lu\n", tst_assert_syscall (time, 0));
  t[0] = tst_assert_syscall (time, t + 1);
  eri_assert (t[0] == t[1]);

  struct eri_tms tms;
  eri_assert (tst_syscall (times, 1) == ERI_EFAULT);
  eri_info ("times: %lu\n", tst_assert_syscall (times, 0));
  tst_assert_syscall (times, &tms);
  eri_info ("utime: %lu, stime: %lu, cutime: %lu, cstime: %lu\n",
	    tms.utime, tms.stime, tms.cutime, tms.cstime);

  eri_assert (tst_syscall (settimeofday, 1, 0) == ERI_EFAULT);

  struct eri_timeval timeval;
  tst_assert_syscall (gettimeofday, 0, 0);
  eri_assert (tst_syscall (gettimeofday, 1, 0) == ERI_EFAULT);
  tst_assert_syscall (gettimeofday, &timeval, 0);
  eri_info ("get time: %lu %lu\n", timeval.sec, timeval.usec);

  eri_assert (tst_syscall (adjtimex, 0) == ERI_EFAULT);
  eri_assert (tst_syscall (clock_adjtime, -1, 0) == ERI_EINVAL);
  eri_assert (tst_syscall (clock_adjtime,
			   ERI_CLOCK_REALTIME, 0) == ERI_EFAULT);

  struct eri_timespec timespec;
  eri_assert (tst_syscall (clock_settime, -1, 0) == ERI_EINVAL);
  eri_assert (tst_syscall (clock_settime,
			   ERI_CLOCK_REALTIME, 0) == ERI_EFAULT);
  tst_assert_syscall (clock_gettime, ERI_CLOCK_REALTIME, &timespec);
  eri_info ("clock realtime: %lu %lu\n", timespec.sec, timespec.nsec);
  uint32_t i, j = 0;
  for (i = 0; i < (timeval.usec + timespec.nsec) % 16; ++i)
    tst_atomic_inc (&j, 0);
  tst_assert_sys_exit (0);
}
