/* vim: set ft=cpp: */

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

static void
write (void)
{
  const char *msg = "test\n";
  tst_assert_syscall (write, 1, msg, eri_strlen (msg));
  struct eri_iovec iov[] = {
    { (void *) msg, eri_strlen (msg) }, { (void *) msg, eri_strlen (msg) }
  };
  tst_assert_syscall (writev, 1, iov, eri_length_of (iov));
}

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");

  write ();

  int32_t fd = tst_assert_syscall (open, "/proc/self/exe",
				   ERI_O_RDONLY | ERI_O_NONBLOCK);
  tst_assert_syscall (close, fd);

  fd = tst_assert_syscall (open, "/proc/self/exe", ERI_O_RDONLY);
  uint8_t buf[3][32];
  tst_assert_syscall (read, fd, buf[0], sizeof buf[0]);
  tst_assert_syscall (lseek, fd, 0, ERI_SEEK_SET);
  struct eri_iovec iov[] = {
    { buf[1], sizeof buf[1] }, { buf[2], sizeof buf[2] }
  };
  tst_assert_syscall (readv, fd, iov, eri_length_of (iov));
  eri_assert (eri_memcmp (buf[0], buf[1], sizeof buf[0]) == 0);
  tst_assert_syscall (close, fd);

  tst_assert_sys_exit (0);
}
