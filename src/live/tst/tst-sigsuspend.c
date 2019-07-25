#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static uint8_t handled;

static void
sig_handler (int32_t sig)
{
  eri_debug ("\n");
  handled = 1;
}

static eri_aligned16 uint8_t stack[1024 * 1024];
static struct tst_live_clone_raise_args raise_args;

eri_noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  uint32_t delay = tst_rand (&rand, 0, 64);
  raise_args.args.top = tst_stack_top (stack);
  raise_args.args.delay = tst_rand (&rand, 0, 64);
  raise_args.count = 1;

  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);

  struct eri_sigaction act = {
    sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);

  eri_sig_empty_set (&mask);

  tst_assert_live_clone_raise (&raise_args);

  tst_yield (delay);
  eri_assert (tst_syscall (rt_sigsuspend, &mask,
			   ERI_SIG_SETSIZE) == ERI_EINTR);
  eri_assert (handled);

  tst_assert_sys_exit (0);
}
