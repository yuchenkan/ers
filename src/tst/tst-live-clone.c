#include <stdint.h>

#include <compiler.h>

#include <live-signal-thread.h>
#include <common.h>

#include <tst/tst-syscall.h>

noreturn void tst_live_start (void);

static aligned16 uint8_t stack[1024 * 1024];
static int32_t ptid, ctid;
static int32_t tls;
static int32_t a[3];

static noreturn void start (int32_t *a0, int32_t *a1, int32_t *a2);

static void start (int32_t *a0, int32_t *a1, int32_t *a2)
{
  eri_debug ("exit %u\n", eri_assert_syscall (gettid));
  tst_syscall (exit, 0);
  eri_assert_unreachable ();
}

noreturn void
tst_live_start (void)
{
  struct eri_sys_clone_args args = {
    ERI_CLONE_SUPPORTED_FLAGS, stack + sizeof stack - 8, &ptid, &ctid, &tls,
    start, a, a + 1, a + 2
  };
  eri_debug ("%u %lx %lx %lx %lx\n",
	     eri_assert_syscall (gettid), args.fn, a, &args, args.stack);
  tst_assert_sys_clone (&args);
  eri_debug ("exit %u\n", eri_assert_syscall (gettid));
  tst_syscall (exit, 0);
  eri_assert_unreachable ();
}
