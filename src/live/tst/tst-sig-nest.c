#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <common/debug.h>

#include <tst/tst-lock.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static eri_aligned16 uint8_t stack[1024 * 1024];

static int32_t pid;
static int32_t tid;

static struct eri_lock int_lock = ERI_INIT_LOCK (1);
static struct eri_lock term_lock = ERI_INIT_LOCK (1);

static void
sig_handler (int32_t sig)
{
  eri_info ("%u\n", sig);
  tst_assert_unlock (sig == ERI_SIGINT ? &int_lock : &term_lock);
}

static void
raise (void *args)
{
  tst_assert_syscall (tgkill, pid, tid, ERI_SIGINT);
  tst_assert_syscall (tgkill, pid, tid, ERI_SIGTERM);
}

eri_noreturn void
tst_live_start (void)
{
  pid = tst_assert_syscall (getpid);
  tid = tst_assert_syscall (gettid);

  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);

  struct eri_sigaction act = {
    sig_handler, ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);
  tst_assert_sys_sigaction (ERI_SIGTERM, &act, 0);

  struct tst_live_clone_args args = {
    .top = tst_stack_top (stack), .fn = raise
  };
  tst_assert_live_clone (&args);

  tst_yield (64);
  eri_sig_empty_set (&mask);
  tst_assert_sys_sigprocmask (&mask, 0);

  tst_assert_lock (&int_lock);
  tst_assert_lock (&term_lock);
  tst_assert_sys_exit (0);
}
