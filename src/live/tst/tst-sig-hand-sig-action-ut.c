#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/malloc.h>
#include <lib/syscall.h>
#include <common/debug.h>

#include <live/rtld.h>
#include <live/thread.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>
#include <live/tst/tst-registers.h>
#include <live/tst/sig-hand-ut.h>
#include <live/tst/tst-sig-hand-ut.h>

static struct eri_live_signal_thread sig_th;

static eri_aligned16 uint8_t stack[8 * 1024 * 1024];

static uint8_t init;
static struct eri_sigframe *init_frame;
static struct eri_siginfo init_info;
static struct eri_mcontext init_ctx;

static uint8_t stepping;
static uint32_t step_count;
static uint32_t raise_at;
static uint8_t reach_done;

#define raise_int(th) \
  do {									\
    struct eri_live_thread *_th = th;					\
    eri_assert_syscall (tgkill, eri_live_thread__get_pid (_th),		\
			eri_live_thread__get_tid (_th), ERI_SIGINT);	\
    eri_assert_unreachable ();						\
  } while (0)

static eri_noreturn void
sig_init_handler (int32_t sig,
		  struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  init_frame = eri_struct_of (info, typeof (*init_frame), info);
  init_info = *info;
  init_ctx = ctx->mctx;
  raise_int (sig_th.th);
}

static void
sig_int_handler (int32_t sig,
		 struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_assert (0);
}

static void
int_hand (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (! init)
    {
      init = 1;
      tst_live_sig_hand_signal (sig_th.th, info, sig_init_handler);
    }
  else
    {
      sig_th.sig_reset = 0;
      ctx->mctx = init_ctx;
      tst_enable_trace ();
      tst_live_sig_hand_signal (sig_th.th, info, sig_int_handler);
    }
}

static eri_noreturn void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  struct eri_siginfo *prev_info = (void *) ctx->mctx.rsi;
  eri_assert (init_frame == eri_struct_of (prev_info,
					    typeof (*init_frame), info));
  eri_assert (ctx->mctx.rdi == init_info.sig);
  eri_assert (prev_info->sig == init_info.sig);
  eri_assert (prev_info->code == init_info.code);
  struct eri_ucontext *prev_ctx = (void *) ctx->mctx.rdx;
#define EQ(creg, reg)	eri_assert (prev_ctx->mctx.reg == init_ctx.reg);
  TST_FOREACH_GENERAL_REG (EQ)
  EQ (RIP, rip)
  eri_assert ((prev_ctx->mctx.rflags & TST_RFLAGS_STATUS_MASK)
		== (init_ctx.rflags & TST_RFLAGS_STATUS_MASK));

  if (reach_done)
    {
      eri_info ("final raise_at = %u\n", raise_at);
      eri_assert_sys_exit (0);
    }

  stepping = 0;
  step_count = 0;
  ++raise_at;

  raise_int (sig_th.th);
}

static void
step_hand (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  //eri_debug ("%lx %u %u %u\n", ctx->mctx.rip, stepping, step_count, raise_at);

  if (ctx->mctx.rip == (uint64_t) eri_assert_sys_sigreturn)
    ((struct eri_sigframe *) (ctx->mctx.rsp - 8))->ctx.mctx.rflags
							|= ERI_RFLAGS_TF;
  if (! stepping)
    {
      if (! sig_th.sig_reset) return;
      stepping = 1;
    }

  if (! stepping) return;
  if (step_count++ != raise_at)
    {
      ctx->mctx.rflags |= ERI_RFLAGS_TF;
      return;
    }
  ctx->mctx.rflags &= ~ERI_RFLAGS_TF;

  eri_debug ("%lx %lx\n", ctx->mctx.rip, ctx->mctx.rflags & ERI_RFLAGS_TF);
  if (ctx->mctx.rip == (uint64_t) sig_int_handler) reach_done = 1;

  tst_live_sig_hand_signal (sig_th.th, info, sig_handler);
}

eri_noreturn void
start (void)
{
  raise_int (sig_th.th);
}

eri_noreturn void
tst_main (void)
{
  tst_live_sig_hand_init_mtpool (&sig_th.pool);

  sig_th.pid = eri_assert_syscall (getpid);
  sig_th.tid = eri_assert_syscall (gettid);

  extern uint8_t tst_main_map_start[];
  extern uint8_t tst_main_map_end[];

  struct eri_live_rtld_args rtld_args = {
    .rsp = (uint64_t) tst_stack_top (stack),
    .rip = (uint64_t) start,
    .map_start = (uint64_t) tst_main_map_start,
    .map_end = (uint64_t) tst_main_map_end
  };

  uint64_t io;
  struct eri_live_thread__create_group_args args = { &rtld_args, 0, &io };

  struct eri_live_thread_group *group
	= eri_live_thread__create_group (&sig_th.pool, &args);

  struct eri_sigaction act = {
    step_hand, ERI_SA_SIGINFO | ERI_SA_ONSTACK | ERI_SA_RESTORER,
    eri_assert_sys_sigreturn
  };
  eri_sig_empty_set (&act.mask);
  eri_assert_sys_sigaction (ERI_SIGTRAP, &act, 0);

  act.act = int_hand;
  eri_assert_sys_sigaction (ERI_SIGINT, &act, 0);

  sig_th.th = eri_live_thread__create_main (group, &sig_th, &rtld_args);
  eri_live_thread__clone_main (sig_th.th);
  eri_live_thread__join (sig_th.th);
  eri_live_thread__destroy (sig_th.th);

  eri_live_thread__destroy_group (group);

  eri_assert_fini_mtpool (&sig_th.pool);
  eri_assert_sys_exit (0);
}
