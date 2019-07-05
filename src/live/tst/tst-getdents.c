#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>
#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");

  int32_t fd = tst_assert_syscall (open, ".",
				   ERI_O_RDONLY | ERI_O_DIRECTORY);
  uint8_t buf[256];
  uint64_t nread, i = 0;
  while ((nread = tst_assert_syscall (getdents, fd, buf, sizeof buf)))
    {
      uint64_t p;
      struct eri_dirent *d;
      for (p = 0; p < nread; p += d->reclen)
	{
	  d = (void *) (buf + p);
	  if (eri_strncmp (d->name, "tst-", 4))
	    tst_assert_printf (i++ ? " %s" : "%s", d->name);
	}
    }
  tst_assert_printf ("\n");

  tst_assert_syscall (close, fd);
  tst_assert_sys_exit (0);
}
