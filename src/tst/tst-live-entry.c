#include <common.h>

#include <tst/tst-syscall.h>
#include <tst/tst-live-entry.h>

struct pack
{
  struct pack *pack;
  struct tst_live_entry_mcontext *tctx;
  uint8_t (*step) (struct tst_live_entry_mcontext *, void *);
  void *args;

  uint64_t fs;
  uint8_t init;
  struct tst_live_entry_mcontext old_tctx;
};

static void
trap (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_debug ("rip = %lx\n", ctx->mctx.rip);

  struct pack *pack = tst_get_tls ();
  if (! pack->init)
    {
#define SAVE(cr, r)	pack->old_tctx.r = ctx->mctx.r;
#define INIT(cr, r)	ctx->mctx.r = pack->tctx->r;
      TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (SAVE)
      TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (INIT)
      ctx->mctx.rflags |= TST_RFLAGS_TRACE_MASK;
      pack->init = 1;
      return;
    }

  struct tst_live_entry_mcontext tctx;
#define GET(cr, r)	tctx.r = ctx->mctx.r;
  TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (GET)

  if (! pack->step (&tctx, pack->args))
    {
#define RESTORE(cr, r)	ctx->mctx.r = pack->old_tctx.r;
      TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (RESTORE)
      ctx->mctx.rflags &= ~TST_RFLAGS_TRACE_MASK;
    }
};

void
tst_live_entry (struct tst_live_entry_mcontext *tctx,
		uint8_t (*step) (struct tst_live_entry_mcontext *, void *),
		void *args)
{
  struct pack pack = { &pack, tctx, step, args };
  tst_assert_syscall (arch_prctl, ERI_ARCH_GET_FS, &pack.fs);
  tst_assert_syscall (arch_prctl, ERI_ARCH_SET_FS, &pack);

  uint8_t sig_stack[8096];
  struct eri_stack old_stack;
  struct eri_stack stack = { (uint64_t) sig_stack, 0, sizeof sig_stack };
  tst_assert_syscall (sigaltstack, &stack, &old_stack);

  struct eri_sigaction old_act;
  struct eri_sigaction act = {
    trap, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_ONSTACK,
    tst_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  tst_assert_sys_sigaction (ERI_SIGTRAP, &act, &old_act);

  struct eri_sigset old_mask;
  struct eri_sigset mask;
  eri_sig_fill_set (&mask);
  eri_sig_del_set (&mask, ERI_SIGTRAP);
  tst_assert_sys_sigprocmask (&mask, &old_mask);

  tst_assert_syscall (tgkill, tst_assert_syscall (getpid),
		      tst_assert_syscall (gettid), ERI_SIGTRAP);

  tst_assert_syscall (arch_prctl, ERI_ARCH_SET_FS, pack.fs);
  tst_assert_syscall (sigaltstack, &old_stack, 0);
  tst_assert_sys_sigaction (ERI_SIGTRAP, &old_act, 0);
  tst_assert_sys_sigprocmask (&old_mask, 0);
}
