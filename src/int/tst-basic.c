#include <compiler.h>
#include <int/tst-syscall.h>

eri_noreturn void tst_main (void);

eri_noreturn void
tst_main (void)
{
  tst_assert_sys_exit (0);
}
