#include <compiler.h>
#include <common.h>

#include <tst/tst-syscall.h>

static uint8_t handled;
static uint8_t sig_stack[8096];

static void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_debug ("\n");
  handled = 1;
  eri_assert (sig == ERI_SIGINT);
  eri_assert (info->code == ERI_SI_TKILL);
  eri_assert (ctx->stack.sp == (uint64_t) sig_stack);
  eri_assert (ctx->stack.flags == ERI_SS_AUTODISARM);
  eri_assert (ctx->stack.size == sizeof sig_stack);

  struct eri_stack stack;
  tst_assert_syscall (sigaltstack, 0, &stack);
  eri_assert (stack.sp == 0);
  eri_assert (stack.flags == ERI_SS_DISABLE);
  eri_assert (stack.size == 0);
}

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  struct eri_stack stack = {
    (uint64_t) sig_stack, ERI_SS_AUTODISARM, sizeof sig_stack
  };
  tst_assert_syscall (sigaltstack, &stack, 0);

  struct eri_sigaction act = {
    sig_handler, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_ONSTACK,
    tst_assert_sys_sigreturn
  };
  tst_assert_sys_sigaction (ERI_SIGINT, &act, 0);

  tst_assert_sys_raise (ERI_SIGINT);
  eri_assert (handled);

  tst_assert_syscall (sigaltstack, 0, &stack);
  eri_assert (stack.sp == (uint64_t) sig_stack);
  eri_assert (stack.flags == ERI_SS_AUTODISARM);
  eri_assert (stack.size == sizeof sig_stack);

  tst_assert_sys_exit (0);
}
