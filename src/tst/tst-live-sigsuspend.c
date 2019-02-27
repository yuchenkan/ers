#include <compiler.h>
#include <common.h>

#include <lib/tst-util.h>
#include <tst/tst-util.h>
#include <tst/tst-syscall.h>

static uint8_t handled;

static void
sig_handler (int32_t sig)
{
  eri_debug ("\n");
  handled = 1;
}

static int32_t pid;
static int32_t tid;

static uint32_t delay[2];

static aligned16 uint8_t stack[1024 * 1024];

static noreturn void start (void);

static noreturn
void start (void)
{
  tst_yield (delay[1]);
  tst_assert_syscall (tgkill, pid, tid, ERI_SIGINT);
  tst_assert_sys_exit (0);
}

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  pid = tst_assert_syscall (getpid);
  tid = tst_assert_syscall (gettid);

  struct tst_rand rand;
  tst_rand_init (&rand);

  delay[0] = tst_rand (&rand, 0, 64);
  delay[1] = tst_rand (&rand, 0, 64);

  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);

  struct eri_sigaction act = {
    sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);

  eri_sig_empty_set (&mask);

  struct eri_sys_clone_args args = {
    ERI_CLONE_SUPPORTED_FLAGS, tst_clone_top (stack), 0, 0, 0, start
  };
  tst_assert_sys_clone (&args);

  tst_yield (delay[0]);
  eri_assert (tst_syscall (rt_sigsuspend, &mask,
			   ERI_SIG_SETSIZE) == ERI_EINTR);
  eri_assert (handled);

  tst_assert_sys_exit (0);
}
