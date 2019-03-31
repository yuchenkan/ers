#include <lib/compiler.h>
#include <lib/syscall.h>
#include <common/common.h>

#include <tst/tst-syscall.h>

eri_noreturn void tst_live_start (void);

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  tst_assert_sys_exit (0);
}
