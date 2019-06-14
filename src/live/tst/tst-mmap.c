#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>

static uint8_t s;
static uint8_t *m;

static void
sig_handler (int32_t sig)
{
  ++s;
  if (s == 1)
    tst_assert_syscall (mprotect, m, 4096, ERI_PROT_WRITE);
  else if (s == 2)
    {
      tst_assert_syscall (munmap, m + 4096, 4096);
      int32_t fd = tst_assert_sys_open ("/proc/self/exe", 1);
      m = (void *) tst_assert_syscall (mmap, m, 8192, ERI_PROT_READ,
			ERI_MAP_PRIVATE | ERI_MAP_FIXED, fd, 0);
      tst_assert_syscall (close, fd);
      uint8_t i, c = *(uint8_t *) m / 4;
      eri_info ("%u\n", c);
      for (i = 0; i < c; ++i) tst_assert_syscall (sched_yield);
      tst_assert_sys_exit (0);
    }
  else eri_assert (0);
}

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");
  uint64_t brk = tst_assert_syscall (brk, 0);
  tst_assert_syscall (brk, brk + 4096);
  *(uint8_t *) brk = 1;

  struct eri_sigaction act = {
    sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  tst_assert_sys_sigaction (ERI_SIGSEGV, &act, 0);

  eri_assert (tst_syscall (mmap, 0, 0) == ERI_EINVAL);

  m = (void *) tst_assert_syscall (mmap, 0, 8192, 0,
			ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  *m = 1;
  tst_assert_syscall (munmap, m, 4096);
  *m = 1;
  eri_assert_unreachable ();
}
