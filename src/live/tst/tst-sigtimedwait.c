#include <lib/compiler.h>
#include <common/common.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

static eri_aligned16 uint8_t stack[1024 * 1024];
static struct tst_sys_clone_raise_args raise_args;

eri_noreturn void tst_live_start (void);

eri_noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  uint32_t delay = tst_rand (&rand, 0, 64);
  tst_sys_clone_raise_init_args (&raise_args, ERI_SIGINT, stack,
				 tst_rand (&rand, 0, 64), 1);

  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);

  tst_assert_sys_clone_raise (&raise_args);

  tst_yield (delay);
  struct eri_siginfo info;
  eri_assert (tst_assert_syscall (rt_sigtimedwait, &mask,
				  &info, 0, ERI_SIG_SETSIZE) == ERI_SIGINT);
  eri_assert (info.sig == ERI_SIGINT);
  eri_assert (info.code == ERI_SI_TKILL);
  eri_assert (info.kill.pid == raise_args.pid);

  struct eri_timespec to = { 0, 0 };
  eri_assert (tst_syscall (rt_sigtimedwait, &mask,
			   0, &to, ERI_SIG_SETSIZE) == ERI_EAGAIN);

  eri_debug ("done\n");
  tst_assert_sys_exit (0);
}
