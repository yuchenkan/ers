#include <stdint.h>

#include <compiler.h>

#include <live-signal-thread.h>
#include <common.h>

#include <tst/tst-syscall.h>
#include <lib/tst-util.h>

static aligned16 uint8_t stack[1024 * 1024];
static int32_t ptid, ctid;
static void *tls = &tls;
static int32_t a[3];

static noreturn void start (int32_t *a0, int32_t *a1, int32_t *a2);

static void start (int32_t *a0, int32_t *a1, int32_t *a2)
{
  eri_assert (a0 == a && a1 == a + 1 && a2 == a + 2);
  int32_t tid = tst_assert_syscall (gettid);
  eri_debug ("tid = %u\n", tid);
  eri_assert (ptid == tid);
  void *new_tls;
  asm ("movq	%%fs:0, %0" : "=r" (new_tls));
  eri_debug ("%lx %lx\n", new_tls, tls);
  eri_assert (new_tls == tls);

  tst_yield (a[1]);
  eri_debug ("exit\n");
  tst_assert_syscall (exit, 0);
  eri_assert_unreachable ();
}

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand);

  a[0] = tst_rand (&rand, 0, 64);
  a[1] = tst_rand (&rand, 0, 64);
  struct eri_sys_clone_args args = {
    ERI_CLONE_SUPPORTED_FLAGS, stack + sizeof stack - 8, &ptid, &ctid, &tls,
    start, a, a + 1, a + 2
  };
  eri_debug ("%lx %lx %lx %lx\n", args.fn, a, &args, args.stack);
  tst_assert_sys_clone (&args);

  tst_yield (a[0]);
  eri_debug ("exit\n");
  tst_assert_syscall (exit, 0);
  eri_assert_unreachable ();
}
