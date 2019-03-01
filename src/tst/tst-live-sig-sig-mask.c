/* vim: set ft=cpp: */

#include <lib/util.h>
#include <tst/tst-live-sig-race.h>

TST_LIVE_SIG_RACE_DEFINE_TST (ERI_EVAL (do {
  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);

  tst_assert_sys_exit_group (0);
} while (0)), 0)
