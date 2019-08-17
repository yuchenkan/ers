#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>

eri_noreturn void
tst_live_start (void)
{
  eri_assert (tst_syscall (sysinfo, 0) == ERI_EFAULT);
  struct eri_sysinfo info;
  eri_assert (tst_syscall (sysinfo, &info) == 0);
  tst_check (info.uptime + info.loads[0] + info.procs + info.mem_unit);
  eri_info ("info.uptime: %lu\n", info.uptime);
  tst_assert_sys_exit (0);
}
