#include <public/public.h>
#define ERI_APPLY_ERS

#include <lib/compiler.h>
#include <lib/util.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>

static uint8_t handled;
static int32_t pid;
static int32_t tid;
static eri_sigset_t old_mask;

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_debug ("\n");
  handled = 1;
  eri_assert (sig == ERI_SIGINT);
  eri_assert (info->code == ERI_SI_TKILL);
  eri_assert (info->kill.pid == pid);
  eri_assert (ctx->stack.sp == 0);
  eri_assert (ctx->stack.flags == ERI_SS_DISABLE);
  eri_assert (ctx->stack.size == 0);
  eri_assert (ctx->mctx.rax == 0);
  eri_assert (ctx->mctx.rdi == pid);
  eri_assert (ctx->mctx.rsi == tid);
  eri_assert (ctx->mctx.rdx == ERI_SIGINT);
  eri_assert (ctx->sig_mask == old_mask);

  eri_sigset_t mask;
  tst_assert_sys_sigprocmask (0, &mask);
  eri_assert (mask == TST_SIGSET_MASK);
}

eri_noreturn void
tst_live_start (void)
{
  pid = tst_assert_syscall (getpid);
  tid = tst_assert_syscall (gettid);

  tst_assert_sys_sigprocmask (0, &old_mask);

  struct eri_sigaction old_act;
  struct eri_sigaction act = {
    sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  tst_assert_sys_sigaction (ERI_SIGINT, &act, &old_act);
  eri_assert (old_act.act == ERI_SIG_DFL);

  eri_info ("%lx\n", &old_act);

  tst_assert_syscall (tgkill, pid, tid, ERI_SIGINT);
  eri_assert (handled);

  eri_sigset_t mask;
  tst_assert_sys_sigprocmask (0, &mask);
  eri_assert (mask == old_mask);

  tst_assert_sys_exit (0);
}
