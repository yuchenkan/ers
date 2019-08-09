#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-atomic.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

static void
check (uint64_t v)
{
  eri_info ("v = %lu\n", v);
  tst_check (v);
}

eri_noreturn void
tst_live_start (void)
{
  eri_info ("start\n");

  uint8_t buf[16];
  eri_assert (tst_syscall (getrandom, buf, sizeof buf, -1) == ERI_EINVAL);
  uint64_t res = tst_syscall (getrandom, buf, sizeof buf,
				ERI_GRND_RANDOM | ERI_GRND_NONBLOCK);
  eri_assert (eri_syscall_is_ok (res) || res == ERI_EAGAIN);

  if (eri_syscall_is_ok (res) && res > 1) check (buf[0] + buf[1]);

  uint8_t buf1[8192 + 2048];
  tst_assert_syscall (getrandom, buf1, sizeof buf1, 0);

  check (buf1[0] + buf1[4096 + 32] + buf1[8192 + 64]);

  eri_assert (tst_syscall (getrandom, 0, 1, 0) == ERI_EFAULT);

  uint8_t *buf2 = tst_assert_live_alloc_boundary (4096 - 512, 4096);
  eri_assert (tst_syscall (getrandom, buf2, 4096, 0) == ERI_EFAULT);

  check (buf2[0] + buf2[2048 + 32] + buf2[2048 + 1024]);

  tst_assert_live_free_boundary (buf2, 4096);

  tst_assert_sys_exit (0);
}
