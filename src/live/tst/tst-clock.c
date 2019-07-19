#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  struct eri_timespec time;
  eri_assert (tst_syscall (clock_settime, -1, 0) == ERI_EINVAL);
  eri_assert (tst_syscall (clock_settime,
			   ERI_CLOCK_REALTIME, 0) == ERI_EFAULT);
  tst_assert_syscall (clock_gettime, ERI_CLOCK_REALTIME, &time);
  eri_info ("realtime %lu %lu\n", time.sec, time.nsec);
  uint32_t i, j = 0;
  for (i = 0; i < time.nsec % 16; ++i) tst_atomic_inc (&j, 0);
  tst_assert_sys_exit (0);
}
