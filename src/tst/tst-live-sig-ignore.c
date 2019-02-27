#include <compiler.h>

#include <tst/tst-syscall.h>

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  struct eri_sigaction act = { ERI_SIG_IGN };
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);
  tst_assert_sys_raise (ERI_SIGINT);
  tst_assert_sys_exit (0);
}
