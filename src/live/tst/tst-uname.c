#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_assert (tst_syscall (uname, 0) == ERI_EFAULT);

  struct eri_utsname utsname;
  tst_assert_syscall (uname, &utsname);

  eri_info ("%s\n", utsname.sysname);
  eri_info ("%s\n", utsname.nodename);
  eri_info ("%s\n", utsname.release);
  eri_info ("%s\n", utsname.version);
  eri_info ("%s\n", utsname.machine);
  eri_info ("%s\n", utsname.domainname);

  tst_assert_sys_exit (0);
}
