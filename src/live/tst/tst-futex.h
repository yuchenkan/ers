#ifndef TST_LIVE_TST_TST_FUTEX_H
#define TST_LIVE_TST_TST_FUTEX_H

#include <stdint.h>

#include<lib/compiler.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static eri_unused uint8_t stack[8][1024 * 1024];

static eri_unused void
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

static eri_unused void
join (struct tst_live_clone_args *args, uint8_t n)
{
  uint8_t i;
  for (i = 0; i < n; ++i)
    tst_assert_sys_futex_wait (&args[i].alive, 1, 0);
}

#endif
