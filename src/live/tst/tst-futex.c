#include <public/public.h>
#define ERI_APPLY_ERS

#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-variable"

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static uint8_t stack[8][1024 * 1024];

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
    tst_atomic_add (&wait_wake_num,
	eri_min (1, tst_assert_syscall (futex, x,
			  cmp ? ERI_FUTEX_CMP_REQUEUE : ERI_FUTEX_REQUEUE,
			  1, 1, x + 1, 1)), 0);

  join (args, 2);
  eri_assert (wait_wake_num == 2);
  wait_wake_num = 0;
}

static void
pi (void *p)
{
  eri_assert (! tst_syscall (futex, p, ERI_FUTEX_LOCK_PI, 0, 0));
  tst_yield (1024);
  eri_assert (! tst_syscall (futex, p, ERI_FUTEX_UNLOCK_PI));
}

static uint64_t try_pi_failed_num;

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
  else tst_atomic_inc (&try_pi_failed_num, 0);
}

static struct eri_timespec
abs_timeout (uint64_t nsec)
{
  struct eri_timespec time;
  tst_assert_syscall (clock_gettime, ERI_CLOCK_MONOTONIC, &time);
  eri_timespec_add_nsec (&time, nsec);
  return time;
}

static uint64_t pi_timedout_nsec;
static uint64_t pi_timedout_num;

static void
pi_timedout (void *p)
{
  struct eri_timespec time = abs_timeout (pi_timedout_nsec);

  uint64_t res = tst_syscall (futex, p, ERI_FUTEX_LOCK_PI, 0, &time);;
  eri_assert (res == 0 || res == ERI_ETIMEDOUT);
  if (res == 0)
    {
      tst_yield (256);
      eri_assert (! tst_syscall (futex, p, ERI_FUTEX_UNLOCK_PI));
    }
  else tst_atomic_inc (&pi_timedout_num, 0);
}

static void
tst_pi (struct tst_rand *rand, void *fn)
{
  eri_info ("pi\n");

  int32_t x = ERI_FUTEX_OWNER_DIED;
  void *a[] = { &x, &x, &x, &x };
  struct tst_live_clone_args args[eri_length_of (a)];
  clone (args, eri_length_of (a), rand, fn, a);

  pi (&x);

  join (args, eri_length_of (a));
  eri_assert (x == 0);
}

struct inval
{
  int32_t *x;
  int32_t val;
};

static uint8_t inval_pi_locked;

static void
inval (void *p)
{
  struct inval *i = p;
  if (i->val)
    {
      tst_yield (96);
      uint64_t res = tst_syscall (futex, i->x,
				  ERI_FUTEX_WAIT_PRIVATE, i->val, 0);
      eri_assert (res == 0 || res == ERI_EAGAIN || res == ERI_EINVAL);
      if (res) inval_pi_locked = 1;
    }
  else
    {
      uint64_t res = tst_syscall (futex, i->x,
				  ERI_FUTEX_LOCK_PI_PRIVATE, 0, 0);
      eri_assert (res == 0 || res == ERI_EINVAL);
      if (res == ERI_EINVAL)
	{
	  tst_atomic_store (i->x, 0, 1);
	  tst_assert_syscall (futex, i->x, ERI_FUTEX_WAKE_PRIVATE, 1);
	}
      else
	tst_assert_syscall (futex, i->x, ERI_FUTEX_UNLOCK_PI_PRIVATE);
    }
}

static void
tst_inval (struct tst_rand *rand)
{
  eri_info ("inval\n");

  int32_t x = tst_assert_syscall (gettid);
  struct inval i[] = { { &x, x }, { &x, 0 } };
  void *a[] = { i, i + 1 };

  struct tst_live_clone_args args[2];
  clone (args, 2, rand, inval, a);

  join (args, 1);
  if (inval_pi_locked)
    tst_assert_syscall (futex, i->x, ERI_FUTEX_UNLOCK_PI_PRIVATE);
  join (args + 1, 1);
}

struct requeue_pi
{
  int32_t *x;
  int32_t *y;
};

static uint64_t requeue_pi_nsec;

static uint64_t requeue_pi_woken;
static uint64_t requeue_pi_req_again;
static uint64_t requeue_pi_req_woken;
static uint64_t requeue_pi_timedout;

static void
requeue_pi (void *p)
{
  struct requeue_pi *r = p;
  struct eri_timespec time = abs_timeout (requeue_pi_nsec);

  uint64_t res = tst_syscall (
		futex, r->x, ERI_FUTEX_WAIT_REQUEUE_PI, 1, &time, r->y);
  eri_assert (res == 0 || res == ERI_EAGAIN || res == ERI_ETIMEDOUT);
  if (res == 0)
    {
      tst_atomic_inc (&requeue_pi_req_woken, 0);
      tst_assert_syscall (futex, r->y, ERI_FUTEX_UNLOCK_PI);
    }
  else if (res == ERI_EAGAIN)
    tst_atomic_inc (&requeue_pi_req_again, 0);
  else tst_atomic_inc (&requeue_pi_timedout, 0);

  tst_atomic_inc (&requeue_pi_woken, 0);
}

static void
tst_requeue_pi (struct tst_rand *rand)
{
  eri_info ("requeue pi\n");

  int32_t x = 1, y = tst_assert_syscall (gettid);
  struct requeue_pi r = { &x, &y };
  void *a[] = { &r, &r, &r, &r, &r, &r };

  struct tst_live_clone_args args[eri_length_of (a)];
  clone (args, eri_length_of (a), rand, requeue_pi, a);

  uint64_t res;
  do
    {
      tst_yield (32);
      res = tst_syscall (futex, r.x, ERI_FUTEX_CMP_REQUEUE_PI,
			 1, 1, r.y, 1);
      if (eri_syscall_is_ok (res))
	{
	  eri_assert (res <= 2);
	  if (res == 2) tst_syscall (futex, r.y, ERI_FUTEX_UNLOCK_PI);
	}
    }
  while (tst_atomic_load (&requeue_pi_woken, 0) != eri_length_of (a));

  join (args, eri_length_of (a));
}

static void
inval_requeue_pi (void *p)
{
  eri_assert (tst_syscall (futex, p,
		ERI_FUTEX_CMP_REQUEUE_PI, 0, 1, &p, 1) == ERI_EINVAL);
  tst_atomic_store ((int32_t *) p, 0, 1);
  tst_assert_syscall (futex, p, ERI_FUTEX_WAKE, 1);
}

static void
tst_inval_requeue_pi (struct tst_rand *rand)
{
  eri_info ("inval requeue pi\n");

  int32_t x = 1, y = tst_assert_syscall (gettid);
  void *a = &x;
  struct tst_live_clone_args args;
  clone (&args, 1, rand, inval_requeue_pi, &a);

  eri_assert (tst_syscall (futex, &x,
		ERI_FUTEX_WAIT_REQUEUE_PI, 1, 0, &y) == ERI_EAGAIN);

  join (&args, 1);
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
  eri_assert (tst_syscall (futex, 0,
			ERI_FUTEX_CMP_REQUEUE_PRIVATE, 1, 1, 0) == ERI_EFAULT);

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

  eri_assert (tst_syscall (futex, &a,
		ERI_FUTEX_CMP_REQUEUE_PI_PRIVATE, 1, 0, 0, 1) == ERI_EAGAIN);
  eri_assert (a == 0);

  eri_assert (tst_syscall (futex, 0,
		ERI_FUTEX_CMP_REQUEUE_PI_PRIVATE, 1, 0, 0, 1) == ERI_EINVAL);
  eri_assert (tst_syscall (futex, 0,
		ERI_FUTEX_CMP_REQUEUE_PI_PRIVATE, 1, 0, &a, 1) == ERI_EFAULT);

  tst_wake_op (&rand);

  tst_requeue (&rand, 0);
  tst_requeue (&rand, 1);

  tst_pi (&rand, pi);

  tst_pi (&rand, try_pi);
  eri_info ("pi try lock failed: %lu\n", try_pi_failed_num);

  pi_timedout_nsec = tst_rand (&rand, 100000, 3000000);
  tst_pi (&rand, pi_timedout);
  eri_info ("pi timedout nesc: %lu, %lu\n",
	    pi_timedout_nsec, pi_timedout_num);

  tst_inval (&rand);
  eri_info ("inval pi locked: %u\n", inval_pi_locked);

  requeue_pi_nsec = tst_rand (&rand, 100000, 300000);
  tst_requeue_pi (&rand);
  eri_info ("requeu pi again: %lu, req: %lu, timedout: %lu\n",
	    requeue_pi_req_again, requeue_pi_req_woken, requeue_pi_timedout);
  eri_assert (requeue_pi_req_again + requeue_pi_req_woken
			+ requeue_pi_timedout == requeue_pi_woken);

  tst_inval_requeue_pi (&rand);
  // TODO

  eri_info ("exit pi\n");
  // TODO

  eri_info ("exit robust\n");
  // TODO

  tst_assert_sys_exit (0);
}
