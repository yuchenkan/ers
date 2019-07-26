#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  int32_t fd = tst_assert_syscall (open, ".",
				   ERI_O_RDONLY | ERI_O_DIRECTORY);
  tst_assert_syscall (chdir, "/proc/self");

  char dir[64];
  eri_assert (tst_syscall (getcwd, 0, 0) == ERI_ERANGE);
  eri_assert (tst_syscall (getcwd, dir, 1) == ERI_ERANGE);
  uint64_t size = tst_assert_syscall (getcwd, dir, sizeof dir);
  eri_assert (eri_strlen (dir) + 1 == size);
  eri_info ("cwd: %s\n", dir);

  char *part = tst_assert_live_alloc_boundary (4, 4096);
  eri_assert (tst_syscall (getcwd, part, 64) == ERI_EFAULT);
  eri_assert (! eri_strncmp (part, dir, 4));
  tst_assert_live_free_boundary (part, 4096);

  tst_assert_syscall (fchdir, fd);
  eri_assert (tst_syscall (chdir, "/proc/self/maps") == ERI_ENOTDIR);
  tst_assert_syscall (close, fd);
  tst_assert_sys_exit (0);
}
