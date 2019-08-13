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

#define NTH	32
#define NPIPE	32
TST_LIVE_SELECT_DEFINE_UTILS (epo, NTH, NPIPE)

static struct epo_data d;

static uint8_t handled;
static void
sig_handler (int32_t sig, struct eri_siginfo *info,
	     struct eri_ucontext *ctx)
{
  handled = 1;
}

static struct eri_epoll_event events[NTH * NPIPE];

static void
run (uint8_t pwait, uint8_t fault)
{
  eri_info ("%u %u\n", pwait, fault);

  handled = 0;

  int32_t epfd = tst_assert_syscall (epoll_create, NTH * NPIPE);
  uint64_t i, j;
  for (i = 0; i < NTH; ++i)
    for (j = 0; j < NPIPE; ++j)
      {
	struct eri_epoll_event event = { ERI_EPOLLIN, i * NPIPE + j };
	tst_assert_syscall (epoll_ctl, epfd, ERI_EPOLL_CTL_ADD,
			    d.pipes[i][j][0], &event);
      }

  struct eri_epoll_event *e = fault
	? tst_assert_live_alloc_boundary (sizeof *e + sizeof e->events, 4096)
	: &events;
  if (fault) e[1].events = 0;

  if (pwait) tst_assert_sys_sigprocmask_all ();

  epo_clone (&d);

  uint64_t left = NTH * NPIPE;
  uint8_t fault_flip = 0, first = 1;
  while (left)
    {
      uint64_t res;
      if (pwait)
	{
	  eri_sigset_t mask;
	  eri_sig_empty_set (&mask);
	  res = tst_syscall (epoll_pwait, epfd, e + fault_flip,
			     NTH * NPIPE, -1, &mask, ERI_SIG_SETSIZE);
	}
      else res = tst_syscall (epoll_wait, epfd, e + fault_flip,
			      NTH * NPIPE, -1);
      eri_assert (eri_syscall_is_ok (res) || res == ERI_EINTR
		  || (fault && res == ERI_EFAULT));
      if (res == ERI_EINTR)
	{
	  eri_assert (handled);
	  eri_info ("intr\n");
	  continue;
	}
      if (! fault) eri_info ("nfds = %lu\n", res);
      if (fault)
	{
	  if (first) tst_check (e[1].events);
	  first = 0;
	  fault_flip = ! fault_flip;
	}
      if (res == ERI_EFAULT) continue;
      for (i = 0; i < res; ++i)
	{
	  eri_assert (e[i].events == ERI_EPOLLIN);
	  epo_read (&d, e[i].data / NPIPE, e[i].data % NPIPE);
	}
      left -= res;
    }

  epo_join (&d);

  if (pwait)
    {
      if (! handled) eri_info ("not handled\n");
      tst_assert_sys_sigprocmask_none ();
    }

  if (fault) tst_assert_live_free_boundary (e, 4096);

  tst_assert_syscall (close, epfd);
}

eri_noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  int32_t epfd = tst_assert_syscall (epoll_create, 1);
  eri_assert (tst_syscall (epoll_wait, epfd, 0, 1, 0) == 0);
  eri_assert (tst_syscall (epoll_wait, epfd, 0, 0, 0) == ERI_EINVAL);
  eri_assert (tst_syscall (epoll_pwait, epfd, 0, 1, 0, 1) == ERI_EFAULT);
  eri_sigset_t mask;
  eri_assert (tst_syscall (epoll_pwait, epfd, 0, 1, 0, &mask, 0)
							== ERI_EINVAL);
  tst_assert_syscall (close, epfd);

  epo_init (&rand, &d, sig_handler);

  run (0, 0);
  run (1, 0);
  run (0, 1);
  run (1, 1);

  epo_fini (&d);

  tst_assert_sys_exit (0);
}
