#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>

static struct tst_rand rand;
static uint8_t stack[3][1024 * 1024];

static eri_noreturn void
start (uint32_t delay)
{
  tst_yield (delay);
  asm ("syscall" : : "ax" (__NR_sched_yield) : "r11", "cx");
  tst_assert_sys_exit (0);
}

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  tst_rand_init (&rand, 0);

  uint8_t i;
  for (i = 0; i < eri_length_of (stack); ++i)
    {
      struct eri_sys_clone_args args = {
	ERI_CLONE_SUPPORTED_FLAGS, tst_stack_top (stack[i]), 0, 0, 0,
	start, (void *) tst_rand (&rand, 0, 32)
      };

      tst_assert_sys_clone (&args);
    }

  tst_assert_sys_exit (0);
}
