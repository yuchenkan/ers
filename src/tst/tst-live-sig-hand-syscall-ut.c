#include <compiler.h>

#include <public/impl.h>

#include <lib/util.h>
#include <lib/atomic.h>

#include <tst/live-sig-hand-ut.h>
#include <tst/tst-live-sig-hand-ut.h>
#include <tst/generated/registers.h>

void enter (void);
extern uint8_t leave[];
asm ("enter: " ERI_STR (_ERS_SYSCALL (0)) "; leave: ret");

static uint8_t raise;

static uint8_t stepping;
static uint32_t step_count;
static uint32_t raise_at;
static uint8_t reach_done;

static struct eri_mcontext enter_ctx;
static struct eri_mcontext leave_ctx;

#define EQ(creg, reg, c1, c2) \
  eri_assert (c1->reg == c2->reg);

#define assert_eq(c1, c2) \
  do {									\
    struct eri_mcontext *_c1 = c1;					\
    struct eri_mcontext *_c2 = c2;					\
    TST_FOREACH_GENERAL_REG(EQ, _c1, _c2)				\
    eri_assert (_c1->rip == _c2->rip);					\
    eri_assert ((_c1->rflags & TST_RFLAGS_STATUS_MASK)			\
		== (_c2->rflags & TST_RFLAGS_STATUS_MASK));		\
  } while (0)

static noreturn void sig_handler (int32_t sig, struct eri_siginfo *info,
				  struct eri_ucontext *ctx);

static noreturn void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (ctx->mctx.rip == enter_ctx.rip) assert_eq (&ctx->mctx, &enter_ctx);
  else if (ctx->mctx.rip == leave_ctx.rip) assert_eq (&ctx->mctx, &leave_ctx);
  else eri_assert (0);

  if (reach_done)
    {
      eri_info ("final raise_at = %u\n", raise_at);
      eri_assert_sys_exit (0);
    }

  ++raise_at;
  stepping = 0;
  step_count = 0;
  tst_enable_trace ();
  enter ();
  eri_assert_unreachable ();
}

static struct eri_live_signal_thread *sig_th;

void
tst_live_sig_hand_step (int32_t sig, struct eri_siginfo *info,
			struct eri_ucontext *ctx)
{
  //ctx->mctx.rflags |= TST_RFLAGS_TRACE_MASK;

  if (! raise)
    {
      if (ctx->mctx.rip == (uint64_t) enter)
	{
	  ctx->mctx.rax = __NR_read;
	  ctx->mctx.rdi = -1;
	  enter_ctx = ctx->mctx;
	}
      else if (ctx->mctx.rip == (uint64_t) leave)
	{
	  leave_ctx = ctx->mctx;
	  ctx->mctx.rflags &= ~TST_RFLAGS_TRACE_MASK;
	}
      return;
    }

  eri_barrier (); /* XXX: cmp    %rcx,-0x52a(%rip)? */
  if (ctx->mctx.rip == (uint64_t) enter)
    {
      ctx->mctx = enter_ctx;
      stepping = 1;
    }

  if (! stepping) return;
  if (step_count++ != raise_at) return;

  eri_debug ("%lx\n", ctx->mctx.rip);

  if (ctx->mctx.rip == (uint64_t) leave) reach_done = 1;

  tst_live_sig_hand_signal (sig_th->th, info, sig_handler);
}

noreturn void
tst_live_sig_hand_start (void)
{
  sig_th = (void *) __builtin_return_address (0);

  tst_enable_trace ();
  enter ();

  raise = 1;
  tst_enable_trace ();
  enter ();

  eri_assert_unreachable ();
}
