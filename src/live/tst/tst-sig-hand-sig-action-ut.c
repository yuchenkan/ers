#include <compiler.h>
#include <common.h>

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

static struct eri_live_signal_thread sig_th;

static eri_aligned16 uint8_t stack[8 * 1024 * 1024];

static uint8_t raise;

static uint8_t stepping;
static uint32_t step_count;
static uint32_t raise_at;
static uint8_t reach_done;

static struct eri_sigframe *enter_frame;
static struct eri_siginfo enter_info;
static struct eri_mcontext enter_ctx;

#define raise_trap(th) \
  do {									\
    struct eri_live_thread *_th = th;					\
    eri_assert_syscall (tgkill, eri_live_thread__get_pid (_th),		\
			eri_live_thread__get_tid (_th), ERI_SIGTRAP);	\
  } while (0)

static eri_noreturn void sig_handler (int32_t sig, struct eri_siginfo *info,
				      struct eri_ucontext *ctx);

static eri_noreturn void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (! raise)
    {
      enter_frame = tst_struct (info, struct eri_sigframe, info);
      enter_info = *info;
      enter_ctx = ctx->mctx;

      raise = 1;
      goto next;
    }

  struct eri_siginfo *prev_info = (void *) ctx->mctx.rsi;
  eri_assert (enter_frame == tst_struct (prev_info,
					 struct eri_sigframe, info));
  eri_assert (ctx->mctx.rdi == enter_info.sig);
  eri_assert (prev_info->sig == enter_info.sig);
  eri_assert (prev_info->code == enter_info.code);
  struct eri_ucontext *prev_ctx = (void *) ctx->mctx.rdx;
#define EQ(creg, reg)	eri_assert (prev_ctx->mctx.reg == enter_ctx.reg);
  TST_FOREACH_GENERAL_REG (EQ)
  EQ (RIP, rip)
  eri_assert ((prev_ctx->mctx.rflags & TST_RFLAGS_STATUS_MASK)
		== (enter_ctx.rflags & TST_RFLAGS_STATUS_MASK));

  if (reach_done)
    {
      eri_info ("final raise_at = %u\n", raise_at);
      eri_assert_sys_exit (0);
    }

  stepping = 0;
  step_count = 0;
  ++raise_at;

next:
  raise_trap (sig_th.th);
  eri_assert_unreachable ();
}

static void
step_hand (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (! eri_si_single_step (info))
    {
      if (raise) ctx->mctx = enter_ctx;
      tst_live_sig_hand_signal (sig_th.th, info, sig_handler);
      if (raise)
	{
	  ctx->mctx.rflags |= TST_RFLAGS_TRACE_MASK;
	  sig_th.sig_reset = 0;
	}
      return;
    }
  eri_assert (raise);
  //eri_debug ("%lx %u %u\n", ctx->mctx.rip, step_count, raise_at);

  if (! stepping)
    {
      if (! sig_th.sig_reset) return;
      stepping = 1;
    }

  if (! stepping) return;
  if (step_count++ != raise_at) return;

  eri_debug ("%lx\n", ctx->mctx.rip);
  if (ctx->mctx.rip == (uint64_t) sig_handler) reach_done = 1;

  tst_live_sig_hand_signal (sig_th.th, info, sig_handler);
}

eri_noreturn void start (void);

eri_noreturn void
start (void)
{
  raise_trap (sig_th.th);
  eri_assert_unreachable ();
}

eri_noreturn void tst_main (void);

eri_noreturn void
tst_main (void)
{
  tst_live_sig_hand_init_mtpool (&sig_th.pool);
  sig_th.args.stack_size = 8 * 1024 * 1024;

  sig_th.pid = eri_assert_syscall (getpid);
  sig_th.tid = eri_assert_syscall (gettid);

  extern uint8_t tst_live_map_start[];
  extern uint8_t tst_live_map_end[];

  struct eri_live_rtld_args rtld_args = {
    .rsp = (uint64_t) tst_clone_top (stack),
    .rip = (uint64_t) start,
    .map_start = (uint64_t) tst_live_map_start,
    .map_end = (uint64_t) tst_live_map_end
  };

  struct eri_sigaction act = {
    step_hand, ERI_SA_SIGINFO | ERI_SA_ONSTACK | ERI_SA_RESTORER,
    eri_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  eri_assert_sys_sigaction (ERI_SIGTRAP, &act, 0);

  sig_th.th = eri_live_thread__create_main (&sig_th, &rtld_args);
  eri_live_thread__clone_main (sig_th.th);
  eri_live_thread__join (sig_th.th);
  eri_live_thread__destroy (sig_th.th, 0);

  eri_assert_fini_mtpool (&sig_th.pool);
  eri_assert_sys_exit (0);
}
