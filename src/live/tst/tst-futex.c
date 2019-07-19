#include <public/public.h>
#define ERI_APPLY_ERS

#pragma GCC diagnostic ignored "-Wunused-function"

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static uint8_t stack[4][1024 * 1024];

static void
clone (struct tst_live_clone_args *args, uint8_t n,
       struct tst_rand *rand, void *fn, void **a)
{
  uint8_t i;
  for (i = 0; i < n; ++i)
    {
      args[i].top = tst_stack_top (stack[i]);
      args[i].delay = tst_rand (rand, 0, 64);
      args[i].fn = fn;
      args[i].args = a[i];
    }

  uint32_t delay = tst_rand (rand, 0, 48);

  for (i = 0; i < n; ++i)
    tst_assert_live_clone (args + i);

  tst_yield (delay);
}

static void
join (struct tst_live_clone_args *args, uint8_t n)
{
  uint8_t i;
  for (i = 0; i < n; ++i)
    tst_assert_sys_futex_wait (&args[i].alive, 1, 0);
}

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
  struct tst_live_clone_args args[eri_length_of (a)];
  clone (args, eri_length_of (a), rand, wait, a);

  uint64_t res = 0;
  while (res < eri_length_of (a))
    res += tst_assert_syscall (futex, &x, ERI_FUTEX_WAKE_OP_PRIVATE, 1, 1, &y,
		ERI_FUTEX_OP (ERI_FUTEX_OP_ANDN, ~1, ERI_FUTEX_OP_CMP_GT, 0));
  eri_assert (res == eri_length_of (a));
  eri_assert (y == 1);

  join (args, eri_length_of (a));
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
  struct tst_live_clone_args args[eri_length_of (a)];
  clone (args, eri_length_of (a), rand, wait_requeue, a);

  while (tst_atomic_load (&wait_wake_num, 0) != eri_length_of (a))
    tst_atomic_add (&wait_wake_num,
	eri_min (1, tst_assert_syscall (futex, x,
			  cmp ? ERI_FUTEX_CMP_REQUEUE : ERI_FUTEX_REQUEUE,
			  1, 1, x + 1, 1)), 0);

  join (args, eri_length_of (a));
  eri_assert (wait_wake_num == eri_length_of (a));
  wait_wake_num = 0;
}

static void
pi (void *p)
{
  eri_assert (! tst_syscall (futex, p, ERI_FUTEX_LOCK_PI, 0, 0));
  tst_yield (1024);
  eri_assert (! tst_syscall (futex, p, ERI_FUTEX_UNLOCK_PI));
}

static uint64_t try_pi_failed;

static void
try_pi (void *p)
{
  uint64_t res = tst_syscall (futex, p, ERI_FUTEX_TRYLOCK_PI, 0, 0);
  eri_assert (res == 0 || res == ERI_EAGAIN);
  if (res == 0)
    {
      tst_yield (1024);
      eri_assert (! tst_syscall (futex, p, ERI_FUTEX_UNLOCK_PI));
    }
  else tst_atomic_inc (&try_pi_failed, 0);
}

static void
tst_pi (struct tst_rand *rand, uint8_t try)
{
  eri_info ("pi try: %u\n", try);

  int32_t x = ERI_FUTEX_OWNER_DIED;
  void *a[] = { &x, &x };
  struct tst_live_clone_args args[eri_length_of (a)];
  clone (args, eri_length_of (a), rand, try ? try_pi : pi, a);

  pi (&x);

  join (args, eri_length_of (a));
  eri_assert (x == 0);
}

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");

  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  struct eri_timespec to = { 0, 500 };
  int32_t a = 1;

  eri_info ("1\n");

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

  eri_info ("1 pi\n");

  a = 0;
  eri_assert (! tst_syscall (futex, &a, ERI_FUTEX_LOCK_PI_PRIVATE, 0, &to));
  eri_assert (a == tst_assert_syscall (gettid));

  eri_assert (tst_syscall (futex, &a,
		ERI_FUTEX_LOCK_PI_PRIVATE, 0, &to) == ERI_EDEADLK);
  eri_assert (tst_syscall (futex, &a,
		ERI_FUTEX_TRYLOCK_PI_PRIVATE, 0, &to) == ERI_EDEADLK);

  eri_assert (! tst_syscall (futex, &a, ERI_FUTEX_UNLOCK_PI_PRIVATE));
  eri_assert (a == 0);

  tst_wake_op (&rand);

  tst_requeue (&rand, 0);
  tst_requeue (&rand, 1);

  tst_pi (&rand, 0);
  tst_pi (&rand, 1);
  eri_info ("pi try lock failed: %lu\n", try_pi_failed);

  eri_info ("futex requeue pi\n");
  // TODO

  eri_info ("exit pi\n");
  // TODO

  eri_info ("exit robust\n");
  // TODO

  tst_assert_sys_exit (0);
}
