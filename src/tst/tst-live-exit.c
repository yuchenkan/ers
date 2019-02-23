#include <stdint.h>

#include <compiler.h>

#include <live-signal-thread.h>
#include <common.h>

#include <tst/tst-syscall.h>
#include <lib/tst-util.h>

noreturn void tst_live_start (void);

static struct tst_rand rand;
static uint8_t stack[3][1024 * 1024];

static uint8_t group;

static noreturn void start (uint32_t delay, uint32_t i, uint8_t group);

static void
clone (uint64_t i)
{
  if (i == 0) return;

  struct eri_sys_clone_args args = {
    ERI_CLONE_SUPPORTED_FLAGS, stack[i - 1] + sizeof stack[0] - 8, 0, 0, 0,
    start, (void *) tst_rand (&rand, 0, 32), (void *) (i - 1),
    (void *) (uint64_t) (tst_rand (&rand, 0, 5) < group)
  };

  tst_assert_sys_clone (&args);
}

static noreturn void
start (uint32_t delay, uint32_t i, uint8_t group)
{
  clone (i);
  tst_yield (delay);
  tst_assert_syscall_nr (group ? __NR_exit_group : __NR_exit, 0);
  eri_assert_unreachable ();
}

noreturn void
tst_live_start (void)
{
  void **args = __builtin_return_address (0);
  if (*(uint64_t *) args == 2) group = ((const char **) (args + 1)) [1][0] - '0';
  eri_info ("group = %u\n", group);

  tst_rand_init (&rand);

  start (tst_rand (&rand, 0, 32), sizeof stack / sizeof stack[0],
	 tst_rand (&rand, 0, 5) < group);
}
