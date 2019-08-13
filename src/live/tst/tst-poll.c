#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-select.h>

#define NTH	32
#define NPIPE	2
TST_LIVE_SELECT_DEFINE_UTILS (pol, NTH, NPIPE)

static struct pol_data d;

static uint8_t handled;
static void
sig_handler (int32_t sig, struct eri_siginfo *info,
	     struct eri_ucontext *ctx)
{
  handled = 1;
}

static void
run (uint8_t ppol)
{
  eri_info ("%u\n", ppol);
  if (ppol) tst_assert_sys_sigprocmask_all ();

  handled = 0;

  struct eri_pollfd fds[NTH * NPIPE];
  uint64_t i;
  for (i = 0; i < NTH * NPIPE; ++i)
    {
      fds[i].fd = d.pipes[i / NPIPE][i % NPIPE][0];
      fds[i].events = ERI_POLLIN;
    }

  pol_clone (&d);

  uint64_t left = NTH * NPIPE;
  while (left)
    {
      uint64_t res;
      if (ppol)
	{
	  eri_sigset_t mask;
	  eri_sig_empty_set (&mask);
	  res = tst_syscall (ppoll, fds, NTH * NPIPE,
			     0, &mask, ERI_SIG_SETSIZE);
	}
      else res = tst_syscall (poll, fds, NTH * NPIPE, -1);
      eri_xassert (eri_syscall_is_ok (res) || res == ERI_EINTR, eri_info);
      if (res == ERI_EINTR)
	{
	  eri_xassert (handled, eri_info);
	  eri_info ("intr\n");
	  continue;
	}
      eri_info ("nfds = %lu\n", res);
      uint64_t j = 0;
      for (i = 0; i < NTH * NPIPE; ++i)
	if (fds[i].revents)
	  {
	    eri_xassert (fds[i].revents == ERI_POLLIN, eri_info);
	    ++j;
	    pol_read (&d, i / NPIPE, i % NPIPE);
	  }
      eri_xassert (j == res, eri_info);
      left -= j;
    }

  (void) pol_read;

  pol_join (&d);
  if (ppol)
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

  eri_assert (tst_syscall (poll, 0, 0, 0) == 0);
  struct eri_timespec timeout = { 0, 0 };
  eri_assert (tst_syscall (ppoll, 0, 0, &timeout, 0) == 0);
  eri_assert (tst_syscall (poll, 0, 1, 0) == ERI_EFAULT);
  eri_assert (tst_syscall (ppoll, 0, 1, 0, 0) == ERI_EFAULT);

  pol_init (&rand, &d, sig_handler);

  run (0);
  run (1);

  TST_LIVE_SELECT_TIMEOUT (&timeout, nsec, &d,
			   ppoll, 0, 0, &timeout, 0);

  pol_fini (&d);

  tst_assert_sys_exit (0);
}
