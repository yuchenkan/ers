#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  struct eri_rlimit r;
  eri_assert (tst_syscall (setrlimit, -1, &r) == ERI_EINVAL);
  eri_assert (tst_syscall (setrlimit, ERI_RLIMIT_STACK, 0) == ERI_EFAULT);
  tst_assert_syscall (getrlimit, ERI_RLIMIT_STACK, &r);
  eri_info ("stack rlimit: %lu, %lu\n", r.cur, r.max);
  r.cur = eri_max (r.cur, 4096 * 4) - 4096;
  r.max = eri_max (r.max, 4096 * 4);
  tst_assert_syscall (setrlimit, ERI_RLIMIT_STACK, &r);

  int32_t tid = tst_assert_syscall (gettid);
  tst_assert_syscall (prlimit64, tid, ERI_RLIMIT_STACK, 0, &r);
  r.cur -= 4096;
  tst_assert_syscall (prlimit64, tid, ERI_RLIMIT_STACK, &r, 0);
  tst_assert_syscall (prlimit64, tid, ERI_RLIMIT_STACK, 0, 0);

  struct eri_rusage u;
  eri_assert (tst_syscall (getrusage, 0xff, &u) == ERI_EINVAL);
  eri_assert (tst_syscall (getrusage, ERI_RUSAGE_SELF, 0) == ERI_EFAULT);
  tst_assert_syscall (getrusage, ERI_RUSAGE_SELF, &u);

  eri_info ("utime.sec: %lu, .usec: %lu\n", u.utime.sec, u.utime.usec);
  eri_info ("stime.sec: %lu, .usec: %lu\n", u.stime.sec, u.stime.usec);

  tst_assert_sys_exit (0);
}
