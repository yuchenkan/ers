#include <compiler.h>
#include <common.h>

#include <rtld.h>
#include <lib/malloc.h>
#include <lib/syscall.h>

#include <tst/live-sig-hand-ut.h>
#include <tst/tst-live-sig-hand-ut.h>

#include <tst/tst-util.h>
#include <tst/tst-syscall.h>
#include <tst/generated/registers.h>

static aligned16 uint8_t buf[256 * 1024 * 1024];
static struct eri_live_signal_thread sig_th;

struct step
{
  uint8_t raise;
  uint8_t init;
  uint32_t trap_count;

  uint32_t step_count;
  uint32_t raise_at;
  uint8_t reach_done;

  uint8_t trans;

  struct eri_mcontext init_ctx;
  struct eri_mcontext *trap_ctxs;

  uint64_t atomic_init_val;
  uint64_t atomic_fini_val;

  struct tst_live_sig_hand_step step;
};

static struct step step;

#define enter(s)	((void (*) (void)) (s)->step.enter) ()

static aligned16 uint8_t stack[8 * 1024 * 1024];

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
  struct eri_mcontext *start = ! step.trap_count ? &step.init_ctx
					: step.trap_ctxs + step.trap_count - 1;
  struct eri_mcontext *end = step.trans ? step.trap_ctxs + step.trap_count : 0;

  if (ctx->mctx.rip == start->rip) assert_eq (&ctx->mctx, start);
  else if (end && ctx->mctx.rip == end->rip) assert_eq (&ctx->mctx, end);
  else eri_assert (0);

  /* No repeat atomic operation.  */
  if (step.step.atomic)
    {
      if (ctx->mctx.rip == step.step.enter)
	eri_assert (step.step.atomic_val == step.atomic_init_val);
      else if (ctx->mctx.rip == step.step.leave)
	eri_assert (step.step.atomic_val == step.atomic_fini_val);
      else eri_assert (0);
    }

  if (step.reach_done)
    {
      eri_info ("final raise_at = %u\n", step.raise_at);
      eri_assert_sys_exit (0);
    }

  ++step.raise_at;
  step.init = 0;
  step.trans = 0;
  step.trap_count = 0;
  step.step_count = 0;
  tst_enable_trace ();
  enter (&step);
  eri_assert_unreachable ();
}

static void
step_hand (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  //ctx->mctx.rflags |= TST_RFLAGS_TRACE_MASK;

  if (! step.raise)
    {
      if (ctx->mctx.rip == step.step.enter)
	{
	  if (! step.init)
	    {
	      step.step.fix_ctx (&ctx->mctx);
	      step.init_ctx = ctx->mctx;
	      step.init = 1;
	    }
	  else step.trap_ctxs[step.trap_count++] = ctx->mctx;
	}
      else if (ctx->mctx.rip == step.step.leave)
	{
	  step.trap_ctxs[step.trap_count] = ctx->mctx;
	  if (step.step.atomic) step.atomic_fini_val = step.step.atomic_val;
	  ctx->mctx.rflags &= ~TST_RFLAGS_TRACE_MASK;
	}
      return;
    }

  // eri_barrier (); /* XXX: cmp    %rcx,-0x52a(%rip)? */
  if (ctx->mctx.rip == step.step.enter)
    {
      if (! step.init)
	{
	  ctx->mctx = step.init_ctx;
	  if (step.step.atomic) step.step.atomic_val = step.atomic_init_val;
	  step.init = 1;
	}
      else
	{
	  ++step.trap_count;
	  step.trans = 0;
	}
    }
  else step.trans = 1;

  if (! step.init) return;
  if (step.step_count++ != step.raise_at) return;

  eri_debug ("%lx\n", ctx->mctx.rip);

  if (ctx->mctx.rip == step.step.leave) step.reach_done = 1;

  tst_live_sig_hand_signal (sig_th.th, info, sig_handler);
}

noreturn void start (void);

noreturn void
start (void)
{
  tst_enable_trace ();
  enter (&step);

  step.raise = 1;
  step.init = 0;
  step.trap_count = 0;
  tst_enable_trace ();
  enter (&step);

  eri_assert_unreachable ();
}

uint32_t
tst_main (void)
{
  eri_assert_init_pool (&sig_th.pool.pool, buf, sizeof (buf));
  sig_th.args.buf = (uint64_t) buf;
  sig_th.args.buf_size = sizeof buf;
  sig_th.args.stack_size = 8 * 1024 * 1024;

  sig_th.pid = eri_assert_syscall (getpid);
  sig_th.tid = eri_assert_syscall (gettid);

  uint32_t traps = tst_live_sig_hand_init_step (&step.step);
  eri_assert (traps);
  step.trap_ctxs = eri_assert_malloc (&sig_th.pool.pool,
				      sizeof step.trap_ctxs[0] * traps);
  if (step.step.atomic) step.atomic_init_val = step.step.atomic_val;

  extern uint8_t tst_live_map_start[];
  extern uint8_t tst_live_map_end[];

  struct eri_rtld_args rtld_args = {
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

  eri_assert_free (&sig_th.pool.pool, step.trap_ctxs);

  eri_assert_fini_pool (&sig_th.pool.pool);
  return 0;
}
