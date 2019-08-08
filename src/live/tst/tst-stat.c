#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

static char l[2 * ERI_PATH_MAX];

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start %lx\n", l);

  struct eri_stat stat;

  eri_memset (l, '_', sizeof l);
  l[sizeof l - 1] = '\0';
  eri_assert (tst_syscall (stat, l, &stat) == ERI_ENAMETOOLONG);

  tst_assert_syscall (stat, "/dev/zero", &stat);
  eri_assert (tst_syscall (stat, 0, &stat) == ERI_EFAULT);
  eri_assert (tst_syscall (stat, "/dev/zero", 0) == ERI_EFAULT);
  eri_assert (tst_syscall (stat, 0, 0) == ERI_EFAULT);

  int32_t fd = tst_assert_syscall (open, "/dev/zero", ERI_O_RDONLY);
  tst_assert_syscall (fstat, fd, &stat);
  eri_assert (tst_syscall (fstat, -1, "/dev/zero") == ERI_EBADF);
  tst_assert_syscall (close, fd);

  tst_assert_syscall (access, "/dev/zero", ERI_F_OK);
  eri_assert (tst_syscall (access, 0, ERI_F_OK) == ERI_EFAULT);
  eri_assert (tst_syscall (access, "/dev/zero", ERI_X_OK) == ERI_EACCES);

  int32_t dir = tst_assert_syscall (open, "/dev",
				    ERI_O_RDONLY | ERI_O_DIRECTORY);

  tst_assert_syscall (newfstatat, dir, "zero", &stat, 0);
  eri_assert (tst_syscall (newfstatat, dir, 0, &stat, 0) == ERI_EFAULT);
  eri_assert (tst_syscall (newfstatat, dir, "zero", 0, 0) == ERI_EFAULT);
  eri_assert (tst_syscall (newfstatat, dir, 0, 0, 0) == ERI_EFAULT);

  tst_assert_syscall (faccessat, dir, "zero", ERI_F_OK);
  eri_assert (tst_syscall (faccessat, dir, 0, ERI_F_OK) == ERI_EFAULT);

  tst_assert_syscall (close, dir);

  struct eri_ustat ustat;
  tst_assert_syscall (ustat, stat.dev, &ustat);
  eri_info ("ustat.tfree = %u\n", ustat.tfree);

  eri_assert (tst_syscall (ustat, stat.dev, 0) == ERI_EFAULT);
  eri_assert (tst_syscall (ustat, -1, &ustat) == ERI_EINVAL);

  struct eri_statfs statfs;
  tst_assert_syscall (statfs, "/dev", &statfs);

  fd = tst_assert_syscall (open, "/dev/zero", ERI_O_RDONLY);
  tst_assert_syscall (fstatfs, fd, &statfs);
  tst_assert_syscall (close, fd);

  eri_assert (tst_syscall (statfs, "/dev", 0) == ERI_EFAULT);
  eri_assert (tst_syscall (statfs, 0, &statfs) == ERI_EFAULT);
  eri_assert (tst_syscall (statfs, 0, 0) == ERI_EFAULT);

  tst_assert_sys_exit (0);
}
