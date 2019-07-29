#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>
#include <live/tst/tst-futex.h>

static void
wait (void *p)
{
  eri_assert (! tst_syscall (futex, p, ERI_FUTEX_WAIT_PRIVATE, 1, 0));
}

static void
tst_wake_op (struct tst_rand *rand)
{
  eri_info ("wake op\n");

  int32_t x = 1, y = 1;
  void *a[] = { &x, &y };
  struct tst_live_clone_args args[2];
  clone (args, 2, rand, wait, a);

  uint64_t res = 0;
  while (res < 2)
    res += tst_assert_syscall (futex, &x, ERI_FUTEX_WAKE_OP_PRIVATE, 1, 1, &y,
		ERI_FUTEX_OP (ERI_FUTEX_OP_ANDN, ~1, ERI_FUTEX_OP_CMP_GT, 0));
  eri_assert (res == 2);
  eri_assert (y == 1);

  join (args, 2);
}

static uint8_t wait_wake_num;

static void
wait_requeue (void *p)
{
  eri_assert (! tst_syscall (futex, p, ERI_FUTEX_WAIT_PRIVATE, 1, 0));
  tst_atomic_add (&wait_wake_num,
		  tst_assert_syscall (futex, (int32_t *) p + 1,
				      ERI_FUTEX_WAKE_PRIVATE, 1), 0);
}

static void
tst_requeue (struct tst_rand *rand, uint8_t cmp)
{
  eri_info ("wake requeue, cmp: %u\n", cmp);

  int32_t x[2] = { 1, 0 };
  void *a[] = { x, x };
  struct tst_live_clone_args args[2];
  clone (args, 2, rand, wait_requeue, a);

  while (tst_atomic_load (&wait_wake_num, 0) != 2)
    {
      tst_atomic_add (&wait_wake_num,
	  eri_min (1, tst_assert_syscall (futex, x,
			    cmp ? ERI_FUTEX_CMP_REQUEUE_PRIVATE
				: ERI_FUTEX_REQUEUE_PRIVATE,
			    1, 1, x + 1, 1)), 0);
      tst_yield (8);
    }

  join (args, 2);
  eri_assert (wait_wake_num == 2);
  wait_wake_num = 0;
}


eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");

  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  struct eri_timespec to = { 0, 500 };
  int32_t a = 1;

  eri_assert (tst_syscall (futex, &a, -1, 0, &to) == ERI_ENOSYS);

  eri_assert (tst_syscall (futex, &a,
			ERI_FUTEX_WAIT_PRIVATE, 0, &to) == ERI_EAGAIN);

  eri_assert (tst_syscall (futex, &a,
			ERI_FUTEX_WAIT_PRIVATE, 1, &to) == ERI_ETIMEDOUT);
  eri_assert (tst_syscall (futex, &a,
			ERI_FUTEX_WAIT_PRIVATE, 1, 1) == ERI_EFAULT);
  eri_assert (tst_syscall (futex, 0,
			ERI_FUTEX_WAIT_PRIVATE, 1, &to) == ERI_EFAULT);
  eri_assert (tst_syscall (futex, 1,
			ERI_FUTEX_WAIT_PRIVATE, 1, &to) == ERI_EINVAL);

  eri_assert (tst_syscall (futex, &a,
		ERI_FUTEX_WAIT_BITSET_PRIVATE, 1, &to, 0, 0) == ERI_EINVAL);

  eri_assert (! tst_syscall (futex, 0, ERI_FUTEX_WAKE_PRIVATE, 1));
  eri_assert (! tst_syscall (futex, 0, ERI_FUTEX_WAKE_PRIVATE, -1));
  eri_assert (tst_syscall (futex, 1,
			ERI_FUTEX_WAKE_PRIVATE, 1) == ERI_EINVAL);
  eri_assert (tst_syscall (futex, 1,
		ERI_FUTEX_WAKE_BITSET_PRIVATE, 1, 0, 0, 0) == ERI_EINVAL);

  eri_assert (tst_syscall (futex, &a,
			ERI_FUTEX_CMP_REQUEUE_PRIVATE, 1, 1, 0) == ERI_EAGAIN);
  eri_assert (tst_syscall (futex, 0,
			ERI_FUTEX_CMP_REQUEUE_PRIVATE, 1, 1, 0) == ERI_EFAULT);

  tst_wake_op (&rand);

  tst_requeue (&rand, 0);
  tst_requeue (&rand, 1);

  tst_assert_sys_exit (0);
}
