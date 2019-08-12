#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>
#include <common/common.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

#define NPIPE	4
static eri_aligned16 uint8_t stack[NPIPE + 1][1024 * 1024];
static struct tst_live_clone_args pipe_args[NPIPE];
static struct tst_live_clone_raise_args raise_args;

static int32_t pipe[NPIPE][2];

static void
write (void *args)
{
  uint8_t i = (uint64_t) args;
  char buf = 0x12;
  tst_assert_syscall (write, pipe[i][1], &buf, 1);
}

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

  uint8_t i;
  for (i = 0; i < NPIPE; ++i)
    tst_assert_live_clone (pipe_args + i);
  tst_assert_live_clone_raise (&raise_args);

  uint8_t done[NPIPE] = { 0 };
  uint8_t left = NPIPE;
  while (left)
    {
      eri_memset(readfds, 0, sizeof readfds);
      for (i = 0; i < NPIPE; ++i)
	readfds[pipe[i][0] / 8] |= 1 << pipe[i][0] % 8;

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
      int32_t nfds = res;
      eri_info ("nfds = %u\n", nfds);
      uint8_t j = 0;
      for (i = 0; i < NPIPE; ++i)
	if (readfds[pipe[i][0] / 8] & (1 << pipe[i][0] % 8))
	  {
	    ++j;
	    char buf;
	    tst_assert_syscall (read, pipe[i][0], &buf, 1);
	    eri_assert (buf == 0x12);
	    eri_assert (! done[i]);
	    done[i] = 1;
	  }
      eri_assert (nfds == j);
      left -= j;
    }

  for (i = 0; i < NPIPE; ++i)
    tst_assert_sys_futex_wait (&pipe_args[i].alive, 1, 0);
  tst_assert_sys_futex_wait (&raise_args.args.alive, 1, 0);

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

  int32_t max = 0;

  struct eri_sigaction act = {
    sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_RESTART,
    tst_assert_sys_sigreturn
  };
  tst_assert_sys_sigaction (ERI_SIGRTMIN, &act, 0);

  uint8_t i;
  for (i = 0; i < NPIPE; ++i)
    {
      tst_assert_syscall (pipe2, pipe + i, ERI_O_DIRECT | ERI_O_NONBLOCK);
      max = eri_max (max, pipe[i][0]);
      pipe_args[i].top = tst_stack_top (stack[i]);
      pipe_args[i].delay = tst_rand (&rand, 1024, 2048);
      pipe_args[i].fn = write;
      pipe_args[i].args = eri_itop (i);
    }
  raise_args.args.top = tst_stack_top (stack[NPIPE]);
  raise_args.args.delay = tst_rand (&rand, 256, 1024);
  raise_args.sig = ERI_SIGRTMIN;
  raise_args.count = 1;

  run (max, 0);
  run (max, 1);

  for (i = 0; i < NPIPE; ++i)
    {
      tst_assert_syscall (close, pipe[i][0]);
      tst_assert_syscall (close, pipe[i][1]);
    }

  timeval.sec = 1;
  tst_assert_live_clone_raise (&raise_args);
  uint64_t res = tst_syscall (select, 0, 0, 0, 0, &timeval);
  eri_assert (res == 0 || res == ERI_EINTR);
  eri_info ("usec: %lu\n", timeval.usec);
  tst_check (timeval.usec);
  tst_assert_sys_futex_wait (&raise_args.args.alive, 1, 0);

  timespec.sec = 1;
  tst_assert_live_clone_raise (&raise_args);
  res = tst_syscall (pselect6, 0, 0, 0, 0, &timespec);
  eri_assert (res == 0 || res == ERI_EINTR);
  eri_info ("nsec: %lu\n", timespec.nsec);
  tst_check (timespec.nsec);
  tst_assert_sys_futex_wait (&raise_args.args.alive, 1, 0);

  tst_assert_sys_exit (0);
}
