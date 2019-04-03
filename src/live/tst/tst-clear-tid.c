#include <lib/compiler.h>
#include <common/common.h>
#include <live/signal-thread.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static int32_t ctid;
static int32_t set_ctid;

static eri_aligned16 uint8_t stack[1024 * 1024];

static eri_noreturn void start (int32_t *set);

static eri_noreturn void
start (int32_t *set)
{
  if (set) tst_assert_syscall (set_tid_address, set);

  tst_assert_sys_exit (0);
}

eri_noreturn void tst_live_start (void);

eri_noreturn void
tst_live_start (void)
{
  struct eri_sys_clone_args args = {
    ERI_CLONE_SUPPORTED_FLAGS, tst_stack_top (stack), 0, &ctid, 0, start
  };
  ctid = set_ctid = 1;
  tst_assert_sys_clone (&args);
  tst_assert_sys_futex_wait (&ctid, 1, 0);
  args.a0 = &set_ctid;
  ctid = 1;
  tst_assert_sys_clone (&args);
  tst_assert_sys_futex_wait (&set_ctid, 1, 0);
  eri_assert (ctid == 1);
/* TODO: clear tid seg fault */
#if 0
  args.a0 = (void *) 1;
  tst_assert_sys_clone (&args);
  tst_assert_sys_futex_wait (&ctid, 1, 0);
#endif
  tst_assert_sys_exit (0);
}
