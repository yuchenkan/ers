#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

#define NTH	16
static uint8_t stack[NTH][1024 * 1024];
static struct tst_live_clone_args clone_args[NTH];
static eri_lock_t locks[NTH];

static eri_lock_t rwlock;
static int32_t x;

static void
start (void *args)
{
  uint8_t i = (uint64_t) args;
  tst_assert_lock (locks + i);

  uint8_t r = i % 4 == 0;
  int32_t v;
  do
    {
      if (r)
	{
	  tst_assert_rlock (&rwlock);
	  v = x;
	  tst_assert_runlock (&rwlock);
	}
      else
	{
	  tst_assert_wlock (&rwlock);
	  v = ++x;
	  tst_assert_wunlock (&rwlock);
	}

      tst_yield (4);
    }
  while (v < 512);
}

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");

  uint8_t i;
  for (i = 0; i < NTH; ++i)
    {
      locks[i] = 1;
      clone_args[i].top = tst_stack_top (stack[i]);
      clone_args[i].delay = 0;
      clone_args[i].fn = start;
      clone_args[i].args = eri_itop (i);

      tst_assert_live_clone (clone_args + i);
    }

  for (i = 0; i < NTH; ++i)
    tst_assert_unlock (locks + i);

  for (i = 0; i < NTH; ++i)
    tst_assert_sys_futex_wait (&clone_args[i].alive, 1, 0);

  tst_assert_sys_exit (0);
}
