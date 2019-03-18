#include <compiler.h>
#include <common.h>

#include <lib/syscall.h>
#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

static int32_t pid;
static eri_aligned16 uint8_t stack[1024 * 1024];
static int32_t ptid, ctid;
static void *tls = &tls;
static int32_t a[3];

static eri_noreturn void start (int32_t *a0, int32_t *a1, int32_t *a2);

static eri_noreturn void
start (int32_t *a0, int32_t *a1, int32_t *a2)
{
  eri_assert (a0 == a && a1 == a + 1 && a2 == a + 2);
  eri_assert (tst_assert_syscall (getpid) == pid);
  int32_t tid = tst_assert_syscall (gettid);
  eri_debug ("tid = %u\n", tid);
  eri_assert (ptid == tid);
  eri_assert ((uint64_t) &tid >= (uint64_t) stack
	      && (uint64_t) &tid < (uint64_t) stack + sizeof stack);
  void *new_tls = tst_get_tls ();
  eri_debug ("%lx %lx\n", new_tls, tls);
  eri_assert (new_tls == tls);

  tst_yield (a[1]);
  eri_debug ("exit\n");
  tst_assert_sys_exit (0);
}

eri_noreturn void tst_live_start (void);

eri_noreturn void
tst_live_start (void)
{
  pid = tst_assert_syscall (getpid);
  eri_assert (tst_assert_syscall (gettid) == pid);

  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  a[0] = tst_rand (&rand, 0, 64);
  a[1] = tst_rand (&rand, 0, 64);
  struct eri_sys_clone_args args = {
    ERI_CLONE_SUPPORTED_FLAGS, tst_clone_top (stack), &ptid, &ctid, &tls,
    start, a, a + 1, a + 2
  };
  eri_debug ("%lx %lx %lx %lx\n", args.fn, a, &args, args.stack);
  tst_assert_sys_clone (&args);
  eri_assert (args.result == ptid);

  tst_yield (a[0]);
  eri_debug ("exit\n");
  tst_assert_sys_exit (0);
}
