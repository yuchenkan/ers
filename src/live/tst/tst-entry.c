#include <lib/cpu.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-syscall.h>
#include <live/tst/tst-entry.h>

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
  eri_debug ("sig = %u, rip = %lx\n", sig, ctx->mctx.rip);

  struct pack *pack = tst_get_tls ();
  if (! pack->init)
    {
#define SAVE(cr, r)	pack->old_tctx.r = ctx->mctx.r;
#define INIT(cr, r)	ctx->mctx.r = pack->tctx->r;
      TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (SAVE)
      TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (INIT)
      ctx->mctx.rflags |= ERI_RFLAGS_TF;
      pack->init = 1;
      return;
    }

  struct tst_live_entry_mcontext tctx;
#define GET(cr, r)	tctx.r = ctx->mctx.r;
  TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (GET)
  tctx.rflags &= ERI_RFLAGS_STATUS_MASK;

  if (! pack->step (&tctx, pack->args))
    {
#define RESTORE(cr, r)	ctx->mctx.r = pack->old_tctx.r;
      TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (RESTORE)
      ctx->mctx.rflags &= ~ERI_RFLAGS_TF;
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
  eri_debug ("sig_stack = %lx, &pack = %lx\n", sig_stack, &pack);
  struct eri_stack old_stack;
  struct eri_stack stack = {
    (uint64_t) sig_stack, ERI_SS_AUTODISARM, sizeof sig_stack
  };
  tst_assert_syscall (sigaltstack, &stack, &old_stack);

  struct eri_sigaction old_act_trap;
  struct eri_sigaction old_act_segv;
  struct eri_sigaction act = {
    trap, ERI_SA_SIGINFO | ERI_SA_RESTORER | ERI_SA_ONSTACK,
    tst_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  tst_assert_sys_sigaction (ERI_SIGTRAP, &act, &old_act_trap);
  tst_assert_sys_sigaction (ERI_SIGSEGV, &act, &old_act_segv);

  eri_sigset_t old_mask;
  eri_sigset_t mask;
  eri_sig_fill_set (&mask);
  eri_sig_del_set (&mask, ERI_SIGTRAP);
  eri_sig_del_set (&mask, ERI_SIGSEGV);
  tst_assert_sys_sigprocmask (&mask, &old_mask);

  tst_assert_sys_raise (ERI_SIGTRAP);

  tst_assert_syscall (arch_prctl, ERI_ARCH_SET_FS, pack.fs);
  tst_assert_syscall (sigaltstack, &old_stack, 0);
  tst_assert_sys_sigaction (ERI_SIGTRAP, &old_act_trap, 0);
  tst_assert_sys_sigaction (ERI_SIGSEGV, &old_act_segv, 0);
  tst_assert_sys_sigprocmask (&old_mask, 0);
}
