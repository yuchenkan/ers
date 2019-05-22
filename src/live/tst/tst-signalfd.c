#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-rand.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>

static eri_aligned16 uint8_t stack[1024 * 1024];
static eri_aligned16 uint8_t stack2[1024 * 1024];
static struct tst_sys_clone_raise_args raise_args;

static void
assert_raise_read (uint32_t delay, int32_t sig, int32_t fd)
{
  raise_args.sig = sig;
  tst_assert_sys_clone_raise (&raise_args);
  tst_yield (delay);

  struct eri_signalfd_siginfo siginfo;
  tst_assert_syscall (read, fd, &siginfo, sizeof siginfo);

  eri_assert (siginfo.sig == sig);
  eri_assert (siginfo.code == ERI_SI_TKILL);
  eri_assert (siginfo.pid == raise_args.pid);
  tst_assert_sys_futex_wait (&raise_args.alive, 1, 0);
  raise_args.alive = 1;
}

static uint8_t handled;

static void
sig_handler (int32_t sig)
{
  eri_debug ("\n");
  handled = 1;
}

eri_noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand, 0);

  uint32_t delay = tst_rand (&rand, 0, 64);
  tst_sys_clone_raise_init_args (&raise_args, 0, stack,
				 tst_rand (&rand, 0, 64), 1);
  eri_info ("%u %u\n", delay, raise_args.delay);

  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);

  eri_sig_empty_set (&mask);
  eri_sig_add_set (&mask, ERI_SIGINT);

  eri_debug ("einval\n");
  eri_assert (tst_syscall (signalfd4, 1, &mask,
			   ERI_SIG_SETSIZE, 0) == ERI_EINVAL);

  eri_debug ("new fd\n");
  int32_t fd = tst_assert_syscall (signalfd4, -1, &mask,
				   ERI_SIG_SETSIZE, 0);

  assert_raise_read (delay, ERI_SIGINT, fd);

  eri_debug ("change mask\n");
  eri_sig_empty_set (&mask);
  eri_sig_add_set (&mask, ERI_SIGTERM);
  tst_assert_syscall (signalfd4, fd, &mask, ERI_SIG_SETSIZE, 0);

  assert_raise_read (delay, ERI_SIGTERM, fd);

  eri_debug ("fcntl\n");
  tst_assert_syscall (fcntl, fd, ERI_F_SETFL, ERI_O_NONBLOCK);
  eri_assert (tst_syscall (fcntl, fd, ERI_F_GETFL)
				== (ERI_O_NONBLOCK | ERI_O_RDWR));

  eri_debug ("dup2\n");
  tst_assert_syscall (fcntl, fd, ERI_F_SETFL, ERI_O_NONBLOCK);
  int32_t fd2 = tst_assert_syscall (signalfd4, -1, &mask,
				    ERI_SIG_SETSIZE, ERI_SFD_NONBLOCK);
  tst_assert_syscall (fcntl, fd, ERI_F_SETFL, 0);
  tst_assert_syscall (dup2, fd, fd2);

  eri_debug ("close\n");
  tst_assert_syscall (close, fd);
  eri_debug ("ebadf\n");
  eri_assert (tst_syscall (signalfd4, fd, &mask,
			   ERI_SIG_SETSIZE, 0) == ERI_EBADF);

  eri_debug ("dup2 read\n");
  assert_raise_read (delay, ERI_SIGTERM, fd2);

  eri_debug ("eintr\n");
  eri_sig_fill_set (&mask);
  eri_sig_del_set (&mask, ERI_SIGINT);
  tst_assert_sys_sigprocmask (&mask, 0);

  struct eri_sigaction act = {
    sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);

  raise_args.sig = ERI_SIGINT;
  raise_args.count = 0;
  tst_assert_sys_clone_raise (&raise_args);
  tst_yield (delay);

  struct eri_signalfd_siginfo siginfo;
  eri_assert (tst_syscall (read, fd2, &siginfo, sizeof siginfo) == ERI_EINTR);
  eri_assert (handled);

  eri_debug ("exit group\n");
  eri_sig_fill_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);

  struct tst_sys_clone_exit_group_args exit_args;
  tst_sys_clone_exit_group_init_args (&exit_args, stack2, raise_args.delay);
  tst_assert_sys_clone_exit_group (&exit_args);

  tst_yield (delay);
  tst_assert_syscall (read, fd2, &siginfo, sizeof siginfo);
  eri_assert_unreachable ();
}
