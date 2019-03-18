/* vim: set ft=cpp: */

#include <lib/util.h>
#include <live/tst/tst-sig-race.h>

static struct eri_sigset mask;

TST_LIVE_SIG_RACE_DEFINE_TST (eri_sig_fill_set (&mask),
  tst_assert_sys_sigprocmask (&mask, 0), 0, 0)
