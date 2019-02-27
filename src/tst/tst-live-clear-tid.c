#include <compiler.h>

#include <live-signal-thread.h>
#include <common.h>

#include <lib/lock.h>
#include <tst/tst-syscall.h>

static int32_t ctid;
static int32_t set_ctid;

static aligned16 uint8_t stack[1024 * 1024];

static noreturn void start (int32_t *set);

static noreturn void
start (int32_t *set)
{
  if (set) tst_assert_syscall (set_tid_address, set);

  tst_assert_syscall (exit, 0);
  eri_assert_unreachable ();
}

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  struct eri_sys_clone_args args = {
    ERI_CLONE_SUPPORTED_FLAGS, tst_clone_top (stack), 0, &ctid, 0, start
  };
  ctid = set_ctid = 1;
  tst_assert_sys_clone (&args);
  eri_lock (&ctid);
  args.a0 = &set_ctid;
  tst_assert_sys_clone (&args);
  eri_lock (&set_ctid);
  eri_assert (ctid == 1);
  tst_assert_syscall (exit, 0);
  eri_assert_unreachable ();
}
