#include <lib/compiler.h>
#include <int/tst-syscall.h>

static eri_unused int buf[1024 * 1024 * 128];

eri_noreturn void tst_main (void);

eri_noreturn void
tst_main (void)
{
  tst_assert_sys_exit (0);
}
