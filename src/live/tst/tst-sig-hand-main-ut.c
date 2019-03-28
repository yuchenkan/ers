#include <compiler.h>
#include <common.h>

#include <lib/cpu.h>
#include <lib/malloc.h>
#include <lib/syscall.h>
#include <tst/tst-syscall.h>

#include <live/rtld.h>
#include <live/thread.h>

#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>
#include <live/tst/tst-registers.h>
#include <live/tst/sig-hand-ut.h>
#include <live/tst/tst-sig-hand-ut.h>

static uint8_t handled;

static eri_aligned16 uint8_t stack[1024 * 1024];

static eri_noreturn void sig_handler (int32_t sig, struct eri_siginfo *info,
				      struct eri_ucontext *ctx);

static eri_noreturn void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  handled = 1;

#define ZERO(creg, reg) \
  if (__builtin_offsetof (struct eri_mcontext, reg)			\
	!= __builtin_offsetof (struct eri_mcontext, rsp))		\
    eri_assert (ctx->mctx.reg == 0);
  TST_FOREACH_GENERAL_REG (ZERO)

  eri_assert (ctx->mctx.rsp == (uint64_t) tst_clone_top (stack));
  eri_assert (ctx->mctx.rip == 0);
  eri_assert ((ctx->mctx.rflags & TST_RFLAGS_STATUS_MASK) == 0);
  eri_assert_sys_exit (0);
}

static struct eri_live_signal_thread sig_th;

static uint8_t unblocked;

static uint32_t step_count;
static uint32_t raise_at;
static uint8_t reach_done;

static struct eri_ucontext *step_ctx;

static void
step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  step_ctx = ctx;

  ctx->mctx.rflags |= ERI_RFLAGS_TRACE_MASK;

  if (! sig_th.sig_alt_stack_installed) return;

  if (eri_assert_syscall (gettid) == sig_th.tid)
    {
      ctx->mctx.rflags &= ~ERI_RFLAGS_TRACE_MASK;
      return;
    }

  if (! unblocked)
    {
      struct eri_sigset mask;
      eri_assert_sys_sigprocmask (0, &mask);
      if (eri_sig_set_set (&mask, ERI_SIGRTMAX)) return;
      unblocked = 1;
    }

  if (step_count++ != raise_at) return;

  eri_debug ("%lx\n", ctx->mctx.rip);
  if (ctx->mctx.rip == 0) reach_done = 1;

  tst_live_sig_hand_signal (sig_th.th, info, sig_handler);
}

eri_noreturn void
tst_main (void)
{
  tst_live_sig_hand_init_mtpool (&sig_th.pool);

  sig_th.pid = eri_assert_syscall (getpid);
  sig_th.tid = eri_assert_syscall (gettid);

  extern uint8_t tst_live_map_start[];
  extern uint8_t tst_live_map_end[];

  struct eri_live_rtld_args rtld_args = {
    .rsp = (uint64_t) tst_clone_top (stack),
    .map_start = (uint64_t) tst_live_map_start,
    .map_end = (uint64_t) tst_live_map_end
  };

  uint64_t io = 0;
  struct eri_live_thread__create_group_args args = { &rtld_args, &io };
  struct eri_live_thread_group *group
	= eri_live_thread__create_group (&sig_th.pool, &args);

  struct eri_sigaction act = {
    step, ERI_SA_SIGINFO | ERI_SA_ONSTACK | ERI_SA_RESTORER,
    eri_assert_sys_sigreturn
  };
  eri_assert_sys_sigaction (ERI_SIGTRAP, &act, 0);

  struct eri_sigset mask;
  eri_sig_empty_set (&mask);
  eri_sig_add_set (&mask, ERI_SIGRTMAX);
  eri_assert_sys_sigprocmask (&mask, 0);

  for (; ! reach_done; ++raise_at)
    {
      handled = 0;
      step_count = 0;
      sig_th.sig_alt_stack_installed = 0;
      unblocked = 0;

      sig_th.th = eri_live_thread__create_main (group, &sig_th, &rtld_args);

      tst_enable_trace ();
      eri_live_thread__clone_main (sig_th.th);
      eri_live_thread__join (sig_th.th);
      eri_live_thread__destroy (sig_th.th);

      eri_assert (handled);
    }

  eri_info ("final raise_at = %u\n", raise_at);

  eri_live_thread__destroy_group (group);

  eri_assert_fini_mtpool (&sig_th.pool);
  eri_assert_sys_exit (0);
}
