#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  tst_syscall (unlink, "tst-chown.t");
  int32_t fd = tst_assert_syscall (open, "tst-chown.t",
				   ERI_O_RDONLY | ERI_O_CREAT);

  struct eri_stat stat;
  tst_assert_syscall (fstat, fd, &stat);

  eri_info ("%u %u\n", stat.uid, stat.gid);
  tst_assert_syscall (chown, "tst-chown.t", stat.uid, stat.gid);
  tst_assert_syscall (fchown, fd, stat.uid, stat.gid);
  tst_assert_syscall (close, fd);

  fd = tst_assert_syscall (open, ".",
			   ERI_O_RDONLY | ERI_O_DIRECTORY);
  tst_assert_syscall (fchownat, fd, "tst-chown.t", stat.uid, stat.gid, 0);
  tst_assert_syscall (close, fd);

  tst_assert_syscall (unlink, "tst-chown.t");
  tst_assert_sys_exit (0);
}
