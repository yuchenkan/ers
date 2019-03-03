#include <compiler.h>
#include <common.h>

#include <tst/tst-syscall.h>

static uint8_t handled;

static void
sig_handler (int32_t sig)
{
  eri_debug ("\n");
  eri_assert (sig == ERI_SIGINT);
  handled = 1;
}

eri_noreturn void tst_live_start (void);

eri_noreturn void
tst_live_start (void)
{
  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);

  tst_assert_sys_raise (ERI_SIGINT);

  struct eri_sigset set;
  tst_assert_syscall (rt_sigpending, &set, ERI_SIG_SETSIZE);
  eri_assert (eri_sig_set_set (&set, ERI_SIGINT));

  struct eri_sigaction act = {
    sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);

  eri_sig_empty_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);
  eri_assert (handled);

  tst_assert_sys_exit (0);
}
