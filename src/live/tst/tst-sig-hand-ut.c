#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/malloc.h>
#include <lib/syscall.h>

#include <common/debug.h>
#include <live/rtld.h>

#include <tst/tst-syscall.h>

#include <live/tst/tst-util.h>
#include <live/tst/tst-syscall.h>
#include <live/tst/tst-registers.h>
#include <live/tst/sig-hand-ut.h>
#include <live/tst/tst-sig-hand-ut.h>

static eri_aligned16 uint8_t buf[1024];
static struct eri_live_signal_thread sig_th;

struct context
{
  struct eri_mcontext ctx;
  void *mem;
};

struct step
{
  uint8_t raise;
  uint8_t repeated;
  uint32_t count;

  uint32_t step_count;
  uint32_t raise_at;
  uint8_t reach_done;

  uint8_t trans;

  void *mem;

  struct context *ctxs;

  struct tst_live_sig_hand_step step;
};

static struct step step;

asm (ERI_STR (ERI_STATIC_FUNCTION (save_enter))
 "pushq	%rbx;"
 "pushq	%rbp;"
 "pushq	%r12;"
 "pushq	%r13;"
 "pushq	%r14;"
 "pushq	%r15;"
 "subq	$8, %rsp;"
 "call	*%rdi;"
 "addq	$8, %rsp;"
 "popq	%r15;"
 "popq	%r14;"
 "popq	%r13;"
 "popq	%r12;"
 "popq	%rbp;"
 "popq	%rbx;"
 "ret;"
ERI_STR (ERI_END_FUNCTION (save_enter)));

void save_enter (uint64_t entry);
#define enter(s)	save_enter ((s)->step.enter)

static eri_aligned16 uint8_t stack[8 * 1024 * 1024];

static uint8_t
eq (struct eri_mcontext *mctx, struct context *ctx, struct step *step)
{
#define EQ(creg, reg, mc, c)	if (mc->reg != c->ctx.reg) return 0;

  TST_FOREACH_GENERAL_REG (EQ, mctx, ctx)
  EQ (RIP, rip, mctx, ctx)
  if ((mctx->rflags & ERI_RFLAGS_STATUS_MASK)
	!= (ctx->ctx.rflags & ERI_RFLAGS_STATUS_MASK)) return 0;

  if (step->step.mem_size
      && eri_memcmp (step->mem, ctx->mem, step->step.mem_size))
    return 0;
  return 1;
}

static eri_noreturn void
sig_handler (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  struct context *start = step.ctxs + step.count - 1;
  struct context *end = step.trans ? step.ctxs + step.count : 0;

  eri_assert (eq (&ctx->mctx, start, &step)
	      || (end && eq (&ctx->mctx, end, &step)));

  if (step.reach_done)
    {
      eri_info ("final raise_at = %u\n", step.raise_at);
      eri_assert_sys_exit (0);
    }

  ++step.raise_at;
  step.repeated = 0;
  step.count = 0;
  step.step_count = 0;
  step.trans = 0;
  tst_enable_trace ();
  enter (&step);
  eri_assert_unreachable ();
}

static void
step_hand (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  //ctx->mctx.rflags |= ERI_RFLAGS_TF;

  if (! step.raise)
    {
      if (ctx->mctx.rip == step.step.enter && ! step.count)
	step.step.fix_ctx (&ctx->mctx, step.mem);

      if (ctx->mctx.rip == step.step.enter
	  /* XXX: decouple repeating */
	  || (ctx->mctx.rip == step.step.repeat && step.repeated)
	  || ctx->mctx.rip == step.step.leave)
	{
	  struct context *c = step.ctxs + step.count;
	  c->ctx = ctx->mctx;
	  if (ctx->mctx.rip == step.step.repeat)
	    c->ctx.rip = step.step.enter;
	  eri_memcpy (c->mem, step.mem, step.step.mem_size);

	  if (ctx->mctx.rip != step.step.leave) ++step.count;
	}

      if (ctx->mctx.rip == step.step.repeat) step.repeated = 1;

      if (ctx->mctx.rip == step.step.leave)
	ctx->mctx.rflags &= ~ERI_RFLAGS_TF;
      return;
    }

  if (ctx->mctx.rip == step.step.enter
      || (ctx->mctx.rip == step.step.repeat && step.repeated))
    {
      if (! step.count)
	{
	  ctx->mctx = step.ctxs[0].ctx;
	  eri_memcpy (step.mem, step.ctxs[0].mem, step.step.mem_size);
	}
      else step.trans = 0;
      ++step.count;
    }
  else step.trans = 1;

  if (! step.count) return;
  if (ctx->mctx.rip == step.step.repeat) step.repeated = 1;
  if (step.step_count++ != step.raise_at) return;

  eri_debug ("%lx\n", ctx->mctx.rip);

  if (ctx->mctx.rip == step.step.leave) step.reach_done = 1;

  tst_live_sig_hand_signal (sig_th.th, info, sig_handler);
}

eri_noreturn void
start (void)
{
  tst_enable_trace ();
  enter (&step);

  step.raise = 1;
  step.repeated = 0;
  step.count = 0;
  tst_enable_trace ();
  enter (&step);

  eri_assert_unreachable ();
}

eri_noreturn void
tst_main (void)
{
  tst_live_sig_hand_init_mtpool (&sig_th.pool);

  sig_th.pid = eri_assert_syscall (getpid);
  sig_th.tid = eri_assert_syscall (gettid);

  uint32_t cnt = tst_live_sig_hand_init_step (&step.step) + 2;
  step.ctxs = eri_assert_malloc (&sig_th.pool.pool,
				 sizeof step.ctxs[0] * cnt);
  if (step.step.mem_size)
    {
      step.mem = buf;
      uint32_t i;
      for (i = 0; i < cnt; ++i)
	step.ctxs[i].mem = eri_assert_malloc (&sig_th.pool.pool,
					      step.step.mem_size);
    }

  if (step.step.debug == 2) eri_global_enable_debug = 1;
  else if (step.step.debug == 1) eri_enable_debug = 1;

  extern uint8_t tst_main_map_start[];
  extern uint8_t tst_main_map_end[];

  struct eri_live_rtld_args rtld_args = {
    .rsp = (uint64_t) tst_stack_top (stack),
    .rip = (uint64_t) start,
    .map_start = (uint64_t) tst_main_map_start,
    .map_end = (uint64_t) tst_main_map_end
  };

  uint64_t io;
  struct eri_live_thread__create_group_args args = { &rtld_args, 0, 0, &io };

  struct eri_live_thread_group *group
	= eri_live_thread__create_group (&sig_th.pool, &args);

  struct eri_sigaction act = {
    step_hand, ERI_SA_SIGINFO | ERI_SA_ONSTACK | ERI_SA_RESTORER,
    eri_assert_sys_sigreturn
  };
  eri_sig_fill_set (&act.mask);
  eri_assert_sys_sigaction (ERI_SIGTRAP, &act, 0);

  sig_th.th = eri_live_thread__create_main (group, &sig_th, &rtld_args);
  eri_live_thread__clone_main (sig_th.th);
  eri_live_thread__join (sig_th.th);
  eri_live_thread__destroy (sig_th.th);

  if (step.step.mem_size)
    {
      uint32_t i;
      for (i = 0; i < cnt; ++i)
	eri_assert_free (&sig_th.pool.pool, step.ctxs[i].mem);
    }
  eri_assert_free (&sig_th.pool.pool, step.ctxs);

  eri_live_thread__destroy_group (group);

  eri_assert_fini_mtpool (&sig_th.pool);
  eri_assert_sys_exit (0);
}
