#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static uint8_t handled;

static void
sig_handler (int32_t sig)
{
  eri_debug ("\n");
  eri_assert (sig == ERI_SIGINT);
  handled = 1;
}

eri_noreturn void
tst_live_start (void)
{
  tst_assert_sys_sigprocmask_all ();

  tst_assert_sys_raise (ERI_SIGINT);

  eri_sigset_t set;
  tst_assert_syscall (rt_sigpending, &set, ERI_SIG_SETSIZE);
  eri_assert (eri_sig_set_set (&set, ERI_SIGINT));

  struct eri_sigaction act = {
    sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);

  tst_assert_sys_sigprocmask_none ();
  eri_assert (handled);

  tst_assert_sys_exit (0);
}
