#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  uint32_t umask = 0700;
  eri_info ("%lu\n", tst_assert_syscall (umask, umask));
  eri_assert (umask == tst_assert_syscall (umask, 0755));
  tst_assert_sys_exit (0);
}
