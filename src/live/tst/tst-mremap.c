#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

eri_noreturn void
tst_live_start (void)
{
  uint64_t m = tst_assert_syscall (mmap, 0, 4096 * 4, 0,
			ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  eri_info ("m = %lx\n", m);
  tst_assert_syscall (munmap, m + 4096, 4096 * 3);
  m = tst_assert_syscall (mremap, m, 4096, 8192, 0);
  eri_info ("m = %lx\n", m);
  eri_assert (tst_assert_syscall (mremap, m, 8192, 8192,
	ERI_MREMAP_MAYMOVE | ERI_MREMAP_FIXED, m + 8192) == m + 8192);
  tst_assert_sys_exit (0);
}
