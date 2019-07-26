#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

char link[ERI_PATH_MAX];

eri_noreturn void
tst_live_start (void)
{
  tst_syscall (unlink, "tst-link.t");
  tst_syscall (unlink, "tst-link-rename.t");
  tst_syscall (unlink, "tst-symlink.t");
  eri_assert (tst_syscall (readlink, 0,
			   link, ERI_PATH_MAX) == ERI_EFAULT);
  eri_assert (tst_syscall (readlink, "/proc/self/exe", 0, 0) == ERI_EINVAL);
  uint64_t res = tst_assert_syscall (readlink, "/proc/self/exe",
				     link, ERI_PATH_MAX);
  eri_assert (res < ERI_PATH_MAX);
  link[res] = '\0';
  eri_info ("%s\n", link);
  tst_assert_syscall (link, link, "tst-link.t");
  tst_assert_syscall (rename, "tst-link.t", "tst-link-rename.t");
  tst_assert_syscall (unlink, "tst-link-rename.t");
  tst_assert_syscall (symlink, link, "tst-symlink.t");

  tst_assert_syscall (unlink, "tst-symlink.t");

  eri_assert (tst_syscall (link, 0, "tst-link.t") == ERI_EFAULT);
  eri_assert (tst_syscall (link, link, 0) == ERI_EFAULT);
  eri_assert (tst_syscall (link, 0, 0) == ERI_EFAULT);

  tst_assert_sys_exit (0);
}
