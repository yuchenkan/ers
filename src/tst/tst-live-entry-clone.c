#include "tst/tst-live-entry-clone.h"

#include "tst/tst-live-entry-common.h"

#include <stdint.h>

#include "live-entry.h"

#include "lib/tst/tst-util.h"

#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/lock.h"
#include "lib/printf.h"

static int32_t pid;
static int32_t lock;

uint8_t tst_no_tf;
uint8_t tst_raw;

uint8_t tst_child_stack[TST_CHILD_STACK_SIZE];
int32_t *tst_ptid;
int32_t *tst_ctid;

struct tls {
  struct tls *tls;
} tls, *tst_newtls;

static uint8_t thread_started;

static struct eri_live_thread_entry *child_entry;

static uint8_t block_all;

void
tst_child (void *newtls, void *entry)
{
  eri_assert_lprintf (&lock, "[child]\n");

  ++thread_started;
  eri_assert (newtls == &tls);
  eri_assert (tst_newtls == &tls);

  if (! tst_raw) eri_assert (entry == child_entry);

  struct eri_sigset set;
  ERI_ASSERT_SYSCALL (rt_sigprocmask, 0, 0, &set, ERI_SIG_SETSIZE);
  if (block_all) eri_assert (eri_sigset_full (&set));
  else eri_assert (eri_sigset_empty (&set));
}

extern uint8_t tst_clone_raw_enter[];
extern uint8_t tst_clone_raw_leave[];
extern uint8_t tst_clone_raw_nop[];

extern uint8_t tst_clone_enter[];
extern uint8_t tst_clone_leave[];
extern uint8_t tst_clone_nop[];

static struct eri_mcontext before;
static struct eri_mcontext after;
static struct eri_mcontext child_after;
static struct eri_mcontext child_after_nop;

static void
sig_raw (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (ctx->mctx.rip != (uint64_t) tst_clone_raw_enter
      && ctx->mctx.rip != (uint64_t) tst_clone_raw_leave
      && ctx->mctx.rip != (uint64_t) tst_clone_raw_nop)
    return;

  int32_t tid = ERI_ASSERT_SYSCALL_RES (gettid);
  eri_assert_lprintf (&lock, "[raw:%u] sig raw: rip = %lx\n",
		      pid != tid, ctx->mctx.rip);
  if (ctx->mctx.rip == (uint64_t) tst_clone_raw_enter)
    before = ctx->mctx;
  else if (ctx->mctx.rip == (uint64_t) tst_clone_raw_leave)
    after = ctx->mctx;
  else if (pid != tid)
    child_after_nop = ctx->mctx;
}

static uint8_t silence;

static uint8_t stepping;
static uint8_t child_stepping;

static uint32_t steps;
static uint32_t child_steps;

static void
clear_trace_flag (struct eri_mcontext *mctx)
{
  eri_assert (mctx->rflags & ERI_TRACE_FLAG_MASK);
  eri_assert_printf ("[clear_trace_flag:0]\n");

  struct eri_live_entry_syscall_info *info = (void *) mctx->rcx;
  info->tst_clone_tf = ERI_TRACE_FLAG_MASK;
  mctx->rflags &= ~ERI_TRACE_FLAG_MASK;
}

static void
sig_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (silence) return;

  int32_t tid = ERI_ASSERT_SYSCALL_RES (gettid);
  if (ctx->mctx.rip == (uint64_t) eri_live_entry_clone)
    {
      eri_assert (pid == tid);
      clear_trace_flag (&ctx->mctx);
    }

  if (pid == tid && stepping)
    {
      eri_assert_lprintf (&lock, "[step:0] sig step: rsp = %lx, rip = %lx\n",
			  ctx->mctx.rsp, ctx->mctx.rip);
      ++steps;
    }
  else if (pid != tid && child_stepping)
    {
      eri_assert_lprintf (&lock, "[step:1] sig step: rsp = %lx, rip = %lx\n",
			  ctx->mctx.rsp, ctx->mctx.rip);
      ++child_steps;
    }

  if (ctx->mctx.rip == (uint64_t) tst_clone_enter)
    {
      stepping = child_stepping = 1;
      before = ctx->mctx;
    }
  else if (ctx->mctx.rip == (uint64_t) tst_clone_leave)
    {
      if (pid == tid)
	{
	  stepping = 0;
	  tst_assert_mctx_eq (&after, &ctx->mctx,
			      TST_MEQ_NRAX | TST_MEQ_NRCX | TST_MEQ_NRIP);
	  eri_assert (ctx->mctx.rax == *tst_ptid);
	  eri_assert (ctx->mctx.rcx == (uint64_t) tst_clone_leave);
	  eri_assert (ctx->mctx.rip == (uint64_t) tst_clone_leave);
	  after = ctx->mctx;
	}
      else
	{
	  child_stepping = 0;
	  child_after = ctx->mctx;
	}
    }
  else if (pid != tid && ctx->mctx.rip == (uint64_t) tst_clone_nop)
    {
      tst_assert_mctx_eq (&child_after_nop, &ctx->mctx,
			  TST_MEQ_NRCX | TST_MEQ_NRIP);
      eri_assert (ctx->mctx.rcx == (uint64_t) tst_clone_leave);
      eri_assert (ctx->mctx.rip == (uint64_t) tst_clone_nop);
      child_after_nop = ctx->mctx;
    }
}

static struct tst_step step;

static uint8_t trigger_child;
static uint8_t triggered;
uint8_t completed = 1;

int32_t
tst_sig_step_int_check_trigger (int32_t sig, struct eri_siginfo *info,
				struct eri_ucontext *ctx)
{
  if (silence) return 0;

  int32_t tid = ERI_ASSERT_SYSCALL_RES (gettid);
#if 0
  eri_assert_lprintf (&lock, "[step_int:%u] sig check trigger: step = %u, "
		      "trigger = %u rip = %lx\n",
		      pid != tid, step.trigger_steps, step.trigger,
		      ctx->mctx.rip);
#endif

  if (ctx->mctx.rip == (uint64_t) eri_live_entry_clone)
    {
      eri_assert (pid == tid);
      clear_trace_flag (&ctx->mctx);
    }

  if (! trigger_child && pid == tid)
    {
      int32_t res = tst_sig_step_int_check (&step, ctx->mctx.rip,
		    (uint64_t) tst_clone_enter, (uint64_t) tst_clone_leave);

      if (! res && ctx->mctx.rip == (uint64_t) eri_live_entry_clone)
	completed = 1;
      return res;
    }
  else if (trigger_child && pid != tid)
    return tst_sig_step_int_check (&step, ctx->mctx.rip, 0,
				   (uint64_t) tst_clone_leave);
  return 0;
}

static void
sig_step_int_act (int32_t sig, struct eri_siginfo *info,
		  struct eri_ucontext *ctx)
{
  int32_t tid = ERI_ASSERT_SYSCALL_RES (gettid);
  eri_assert_lprintf (&lock,
		      "[step_int:%u] sig trigger act: trigger_child = %u\n",
		      pid != tid, trigger_child);
  eri_assert ((pid == tid) != trigger_child);

  eri_assert (++triggered == 1);
  eri_assert (sig == ERI_SIGINT);

  if (pid == tid)
    {
      tst_assert_mctx_eq (! completed ? &before : &after, &ctx->mctx,
			  ! completed ? 0 : TST_MEQ_NRAX);
      if (completed) eri_assert (ctx->mctx.rax == *tst_ptid);
    }
  else
    tst_assert_mctx_eq (&child_after, &ctx->mctx, 0);

  ctx->mctx.rip = (uint64_t) tst_clone_leave;
}

static void *sig_action;

void
eri_live_start_sig_action (int32_t sig, struct eri_stack *stack,
			   struct eri_live_entry_sigaction_info *info,
			   void *entry)
{
  int32_t tid = ERI_ASSERT_SYSCALL_RES (gettid);
  eri_assert_lprintf (&lock, "[start_sig_action:%u] sig = %u\n",
		      pid != tid, sig);

  stack->size = 0;
  info->rip = (uint64_t) sig_action;
  info->mask.mask_all = 1;
  eri_sigfillset (&info->mask.mask);
}

static uint8_t trap_trace;
static uint8_t child_trap_trace;

static void
sigtrap_act (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  int32_t tid = ERI_ASSERT_SYSCALL_RES (gettid);
  eri_assert_lprintf (&lock, "[trap:%u]: rip = %lx\n",
		      pid != tid, ctx->mctx.rip);

  if (pid == tid && trap_trace)
    {
      if (trap_trace == 1)
	{
	  tst_assert_mctx_eq (&after, &ctx->mctx, TST_MEQ_NRAX);
	  eri_assert (ctx->mctx.rax == *tst_ptid);
	}
      else
	eri_assert (ctx->mctx.rip != (uint64_t) tst_clone_leave);
      ++trap_trace;
    }
  else if (pid != tid && child_trap_trace)
    {
      if (child_trap_trace == 1)
	tst_assert_mctx_eq (&child_after_nop, &ctx->mctx, 0);
      else
	eri_assert (ctx->mctx.rip != (uint64_t) tst_clone_nop);
      ++child_trap_trace;
    }

  if (ctx->mctx.rip == (uint64_t) tst_clone_enter)
    trap_trace = child_trap_trace = 1;
}

void
eri_live_start_thread (void *thread)
{
  ++thread_started;
  eri_assert_lprintf (&lock, "[start_thread]\n");
}

static struct tst_rand rand;

int8_t
eri_live_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
		  uint64_t a3, uint64_t a4, uint64_t a5,
		  struct eri_live_entry_syscall_info *info,
		  void *entry)
{
  eri_assert (info->rax == __NR_clone);
  silence = 1;
  eri_assert_printf ("[syscall]\n");

  int32_t flags = (int32_t) a0;
  uint64_t user_child_stack = a1;
  int32_t *ptid = (void *) a2;
  int32_t *ctid = (void *) a3;
  void *newtls = (void *) a4;

  eri_assert (flags == ERI_SUPPORTED_CLONE_FLAGS);
  eri_assert (user_child_stack
		== (uint64_t) tst_child_stack + TST_CHILD_STACK_SIZE);
  eri_assert (ptid == tst_ptid);
  eri_assert (ctid == tst_ctid);
  eri_assert (newtls == tst_newtls);

  silence = 0;

  struct eri_live_entry_clone_info clone_info = {
    flags, user_child_stack, ptid, ctid, newtls
  };

  uint8_t done = eri_live_entry_clone (entry, child_entry, &clone_info, info);
  eri_assert (done == 0 || done == 1);
  return done;
}

uint64_t tst_clone (void);

static void
clone (void)
{
  uint64_t res = tst_clone ();
  if (completed)
    {
      eri_assert ((int64_t) res > 0);
      eri_assert (*tst_ptid == res);
      eri_lock (tst_ctid);
      eri_assert (thread_started == 1 + ! tst_raw);

      thread_started = 0;
      *tst_ptid = 0;
      *tst_ctid = 1;
    }
  else
    {
      eri_assert (thread_started == 0);
      eri_assert (*tst_ptid == 0);
      eri_assert (*tst_ctid == 1);
    }
}

static struct tst_context ctx;

static uint8_t *child_entry_buf;
static uint8_t child_stack[2 * 1024 * 1024];
static uint8_t child_sig_stack[ERI_LIVE_SIG_STACK_SIZE];

static uint8_t *entry_buf;
static uint8_t stack[2 * 1024 * 1024];
static uint8_t sig_stack[ERI_LIVE_SIG_STACK_SIZE];
static struct eri_live_thread_entry *entry;

static void
step_int (uint8_t child)
{
  eri_assert_printf ("[step_int:%u] enter\n", child);

  trigger_child = child;
  completed = child;
#define STEPS	(child ? child_steps : steps)
  for (step.trigger = 0; step.trigger <= STEPS; ++step.trigger)
    {
      eri_assert_printf ("[step_int:%u] trigger at step %u\n",
			 child, step.trigger);

      child_entry = tst_init_live_thread_entry (&rand, child_entry_buf,
			child_stack, sizeof child_stack, child_sig_stack);

      if (child) step.stepping = 1;

      tst_live_entry (&ctx);

      eri_tst_live_assert_thread_entry (entry);
      if (completed)
	eri_tst_live_assert_thread_entry (child_entry);
      eri_assert ((step.trigger >= STEPS) != triggered);

      triggered = 0;
      step.trigger_steps = 0;
      completed = child;
    }

  eri_assert_printf ("[step_int:%u] leave\n", child);
}

uint64_t
tst_main (void)
{
  pid = ERI_ASSERT_SYSCALL_RES (getpid);

  static int32_t ptid, ctid = 1;
  tst_ptid = &ptid;
  tst_ctid = &ctid;

  tst_newtls = tls.tls = &tls;

  tst_rand_seed (&rand, pid);

  tst_rand_fill (&rand, &ctx, sizeof ctx);
  ctx.rflags &= TST_RFLAGS_STATUS_MASK;
  ctx.rflags &= ~ERI_TRACE_FLAG_MASK;
  uint8_t user_stack[8192];
  ctx.rsp = (uint64_t) user_stack + sizeof user_stack;
  ctx.rip = (uint64_t) clone;

  uint8_t bufs[2][ERI_LIVE_THREAD_ENTRY_SIZE];
  child_entry_buf = bufs[0];
  entry_buf = bufs[1];
  entry = tst_init_live_thread_entry (&rand, entry_buf,
				      stack, sizeof stack, sig_stack);

  struct eri_stack st = { (uint64_t) sig_stack, 0, ERI_LIVE_SIG_STACK_SIZE };
  ERI_ASSERT_SYSCALL (sigaltstack, &st, 0);

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_GS, entry);

  child_entry = tst_init_live_thread_entry (&rand, child_entry_buf,
			child_stack, sizeof child_stack, child_sig_stack);

  tst_no_tf = 1;
  tst_live_entry (&ctx);
  eri_tst_live_assert_thread_entry (entry);
  eri_tst_live_assert_thread_entry (child_entry);

  child_entry = tst_init_live_thread_entry (&rand, child_entry_buf,
			child_stack, sizeof child_stack, child_sig_stack);

  block_all = 1;
  tst_block_all_signals ();
  tst_live_entry (&ctx);
  eri_tst_live_assert_thread_entry (entry);
  eri_tst_live_assert_thread_entry (child_entry);
  tst_unblock_all_signals ();
  block_all = 0;

  eri_assert_printf ("[raw] setup\n");

  tst_no_tf = 0;
  struct eri_sigaction sa = {
    sig_raw, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
  };
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  tst_raw = 1;
  tst_live_entry (&ctx);

  eri_assert_printf ("[step] setup\n");

  entry->tst_skip_ctf = 1;
  child_entry->tst_skip_ctf = 1;

  sa.act = sig_step;
  sa.flags |= ERI_SA_ONSTACK;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  child_entry = tst_init_live_thread_entry (&rand, child_entry_buf,
			child_stack, sizeof child_stack, child_sig_stack);

  tst_raw = 0;
  tst_live_entry (&ctx);

  eri_tst_live_assert_thread_entry (entry);
  eri_tst_live_assert_thread_entry (child_entry);
  eri_assert (! stepping && ! child_stepping && steps && child_steps);

  eri_assert_printf ("[step_int] setup\n");

  sa.act = tst_sig_step_int_trigger;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  sig_action = sig_step_int_act;

  step_int (0);
  step_int (1);

  eri_assert_printf ("[trap] setup\n");

  entry->tst_skip_ctf = 0;
  child_entry->tst_skip_ctf = 0;

  sa.act = eri_live_entry_sigaction;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  sig_action = sigtrap_act;

  completed = 1;
  tst_live_entry (&ctx);
  eri_tst_live_assert_thread_entry (entry);
  eri_tst_live_assert_thread_entry (child_entry);
  eri_assert (trap_trace > 1 && child_trap_trace > 1);

  eri_assert_printf ("[done]\n");
  return 0;
}
