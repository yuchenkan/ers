/* vim: set ft=cpp: */

#include <common.h>
#include <lib/util.h>
#include <tst/tst-live-sig-race.h>

static uint8_t handled;

extern uint8_t skip[];

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_debug ("\n");
  ctx->mctx.rip = (uint64_t) skip;
  handled = 1;
}

TST_LIVE_SIG_RACE_DEFINE_TST (ERI_EVAL (do {
  struct eri_sigaction act = {
    sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER, tst_assert_sys_sigreturn
  };
  tst_assert_sys_sigaction (ERI_SIGSEGV, &act, 0);
} while (0)), ERI_EVAL (do {
  asm ("movq	$0, %rax; movq	$0, (%rax); skip:");
  eri_assert (handled);
} while (0)), 0);
