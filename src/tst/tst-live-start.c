#include <compiler.h>
#include <common.h>

#include <lib/syscall.h>
#include <tst/tst-syscall.h>

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  eri_debug ("\n");
  tst_assert_sys_exit (0);
}
