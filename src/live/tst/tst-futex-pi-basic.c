#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");

  int32_t a = 0;
  struct eri_timespec to = { 0, 500 };

  eri_assert (! tst_syscall (futex, &a, ERI_FUTEX_LOCK_PI_PRIVATE, 0, &to));
  eri_assert (a == tst_assert_syscall (gettid));

  eri_assert (tst_syscall (futex, &a,
		ERI_FUTEX_LOCK_PI_PRIVATE, 0, &to) == ERI_EDEADLK);
  eri_assert (tst_syscall (futex, &a,
		ERI_FUTEX_TRYLOCK_PI_PRIVATE, 0, &to) == ERI_EDEADLK);

  eri_assert (! tst_syscall (futex, &a, ERI_FUTEX_UNLOCK_PI_PRIVATE));
  eri_assert (a == 0);

  eri_assert (tst_syscall (futex, &a,
		ERI_FUTEX_CMP_REQUEUE_PI_PRIVATE, 1, 0, 0, 1) == ERI_EAGAIN);
  eri_assert (a == 0);

  eri_assert (tst_syscall (futex, 0,
		ERI_FUTEX_CMP_REQUEUE_PI_PRIVATE, 1, 0, 0, 1) == ERI_EINVAL);
  eri_assert (tst_syscall (futex, 0,
		ERI_FUTEX_CMP_REQUEUE_PI_PRIVATE, 1, 0, &a, 1) == ERI_EFAULT);

  tst_assert_sys_exit (0);
}
