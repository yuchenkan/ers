/* vim: set ft=cpp: */

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  int32_t fd = tst_assert_syscall (open, "/proc/self/exe",
				   ERI_O_RDONLY | ERI_O_NONBLOCK);
  tst_assert_syscall (close, fd);

  fd = eri_assert_syscall (open, "/proc/self/exe", ERI_O_RDONLY);
  uint8_t buf[2][32];
  eri_assert_syscall (read, fd, buf[0], sizeof buf[0]);
  eri_assert_syscall (lseek, fd, 0, ERI_SEEK_SET);
  eri_assert_syscall (read, fd, buf[1], sizeof buf[1]);
  eri_assert (eri_memcmp (buf[0], buf[1], sizeof buf[0]) == 0);
  eri_assert_syscall (close, fd);

  tst_assert_sys_exit (0);
}
