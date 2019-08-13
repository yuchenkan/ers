#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>
#include <common/common.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-select.h>

#define NTH	4
#define NPIPE	2
TST_LIVE_SELECT_DEFINE_UTILS (sel, NTH, NPIPE)

static struct sel_data d;

static uint8_t handled;
static void
sig_handler (int32_t sig, struct eri_siginfo *info,
	     struct eri_ucontext *ctx)
{
  handled = 1;
}

static void
run (int32_t max, uint8_t psel)
{
  eri_info ("%u\n", psel);

  handled = 0;
  uint8_t readfds[eri_syscall_fd_set_bytes(max + 1)];

  if (psel) tst_assert_sys_sigprocmask_all ();

  sel_clone (&d);

  uint64_t left = NTH * NPIPE;
  while (left)
    {
      eri_memset(readfds, 0, sizeof readfds);
      uint64_t i, j;
      for (i = 0; i < NTH; ++i)
	for (j = 0; j < NPIPE; ++j)
	  readfds[d.pipes[i][j][0] / 8] |= 1 << d.pipes[i][j][0] % 8;

      uint64_t res;
      if (psel)
	{
	  struct
	    {
	      eri_sigset_t mask;
	      uint64_t sig_setsize;
	    } data = { .sig_setsize = ERI_SIG_SETSIZE };
	  eri_sig_empty_set (&data.mask);
	  res = tst_syscall (pselect6, max + 1, readfds, 0, 0, 0, &data);
	}
      else res = tst_syscall (select, max + 1, readfds, 0, 0, 0);
      eri_assert (eri_syscall_is_ok (res) || res == ERI_EINTR);
      if (res == ERI_EINTR)
	{
	  eri_assert (handled);
	  eri_info ("intr\n");
	  continue;
	}
      eri_info ("nfds = %lu\n", res);
      uint64_t k = 0;
      for (i = 0; i < NTH; ++i)
	for (j = 0; j < NPIPE; ++j)
	  if (readfds[d.pipes[i][j][0] / 8] & (1 << d.pipes[i][j][0] % 8))
	    {
	      ++k;
	      sel_read (&d, i, j);
	    }
      eri_assert (res == k);
      left -= k;
    }

  sel_join (&d);

  if (psel)
    {
      if (! handled) eri_info ("not handled\n");
      tst_assert_sys_sigprocmask_none ();
    }
}

eri_noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  eri_assert (tst_syscall (select, 0, 0, 0, 0, 1) == ERI_EFAULT);
  struct eri_timeval timeval = { 0, 0 };
  tst_assert_syscall (select, 0, 0, 0, 0, &timeval);
  struct eri_timespec timespec = { 0, 0 };
  tst_assert_syscall (pselect6, 0, 0, 0, 0, &timespec, 0);

  sel_init (&rand, &d, sig_handler);

  int32_t max = 0;

  uint64_t i, j;
  for (i = 0; i < NTH; ++i)
    for (j = 0; j < NPIPE; ++j)
      max = eri_max (d.pipes[i][j][0], max);
  eri_info ("%lu\n", max);

  run (max, 0);
  run (max, 1);

  TST_LIVE_SELECT_TIMEOUT (&timeval, usec, &d,
			   select, 0, 0, 0, 0, &timeval);

  TST_LIVE_SELECT_TIMEOUT (&timespec, nsec, &d,
			   pselect6, 0, 0, 0, 0, &timespec);

  sel_fini (&d);

  tst_assert_sys_exit (0);
}
