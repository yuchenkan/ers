#include "tst/tst-live-entry-common.h"

#include "lib/tst/tst-util.h"

#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/printf.h"

#include "live.h"
#include "live-entry.h"

static uint8_t restart_no_handler;

int8_t
eri_live_ignore_signal (int32_t sig, struct eri_siginfo *info,
			struct eri_ucontext *ctx, int32_t syscall)
{
  eri_assert_printf ("[eri_live_ignore_signal] rip = %lx, syscall = %x\n",
		     ctx->mctx.rip, syscall);

  if (syscall == __NR_gettid) return 0;

  if (syscall != -1)
    {
      ctx->mctx.rip -= 2;
      ctx->mctx.rax = __NR_gettid;
      return restart_no_handler ? 1 : -1;
    }

  return 1;
}

static uint8_t syscall;
static uint8_t stepping;
static uint8_t triggered;

static struct eri_mcontext before, after;

extern uint8_t tst_syscall_enter[];
extern uint8_t tst_syscall_leave[];
extern uint8_t tst_sync_async_enter[];
extern uint8_t tst_sync_async_leave[];

void
eri_live_start_sig_action (int32_t sig, struct eri_stack *stack,
			   struct eri_live_entry_sigaction_info *info,
			   void *entry)
{
  eri_assert_printf ("[eri_live_start_sig_action]\n");

  struct eri_mcontext *mctx = &((struct eri_ucontext *) info->rdx)->mctx;
  ++triggered;
  if (syscall)
    {
      if (! restart_no_handler && triggered == 1)
	{
	  tst_assert_mctx_eq (&before, mctx, TST_MEQ_NRAX | TST_MEQ_NRIP);
	  eri_assert (mctx->rax == __NR_restart_syscall);
	  eri_assert (mctx->rip == (uint64_t) tst_syscall_enter);
	  mctx->rax = __NR_gettid;
	}
      else
	{
	  eri_assert (triggered == (restart_no_handler ? 1 : 2));
	  tst_assert_mctx_eq (&after, mctx, TST_MEQ_NRIP | TST_MEQ_NRCX);
	  eri_assert (mctx->rip == (uint64_t) tst_syscall_leave);
	  eri_assert (mctx->rcx == (uint64_t) tst_syscall_leave);
	  stepping = 0;
	}
    }
  else
    {
      eri_assert (triggered == 1);
      tst_assert_mctx_eq (&after, mctx, TST_MEQ_NRIP);
      eri_assert (mctx->rip == (uint64_t) tst_sync_async_leave);
      stepping = 0;
    }

  info->rip = 0;
}

int8_t
eri_live_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
		  uint64_t a3, uint64_t a4, uint64_t a5,
		  struct eri_live_entry_syscall_info *info,
		  void *entry)
{
  return eri_live_entry_do_syscall (a0, a1, a2, a3, a4, a5,
				    info, entry);
}

void
eri_live_sync_async (uint64_t cnt, void *entry)
{
}

void
sig_raw (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  extern uint8_t tst_raw_syscall_enter[];
  extern uint8_t tst_raw_syscall_leave[];
  extern uint8_t tst_raw_sync_async_leave[];

  if (syscall)
    {
      if (ctx->mctx.rip == (uint64_t) tst_raw_syscall_enter)
        before = ctx->mctx;
      else if (ctx->mctx.rip == (uint64_t) tst_raw_syscall_leave)
        after = ctx->mctx;
    }
  else if (ctx->mctx.rip == (uint64_t) tst_raw_sync_async_leave)
    after = ctx->mctx;
}

static struct eri_live_thread_entry *entry;

int32_t
tst_sig_step_int_check_trigger (int32_t sig, struct eri_siginfo *info,
				struct eri_ucontext *ctx)
{
  eri_assert_printf ("[tst_sig_step_int_check_trigger] "
		     "stepping = %u rip = %lx\n",
		     stepping, ctx->mctx.rip);

  int32_t res = 0;
  if (syscall)
    {
      if (stepping
	  && (! entry->restart_syscall
	      || ctx->mctx.rip == (uint64_t)
			ERI_TST_LIVE_COMPLETE_START_SYMBOL (do_syscall)))
	res = ERI_SIGINT;

      if (ctx->mctx.rip == (uint64_t) tst_syscall_enter) stepping = 1;
    }
  else
    {
      if (stepping) res = ERI_SIGINT;
      if (ctx->mctx.rip == (uint64_t) tst_sync_async_enter) stepping = 1;
    }
  return res;
}

void tst_raw_syscall (void);
void tst_raw_sync_async (void);

void tst_syscall (void);
void tst_sync_async (void);

static uint8_t user_stack[1024 * 1024];
static uint8_t stack[1024 * 1024];
static uint8_t sig_stack[ERI_LIVE_SIG_STACK_SIZE];

static void
tst (struct tst_rand *rand)
{
  struct tst_context ctx;
  tst_rand_fill (rand, &ctx, sizeof ctx);
  ctx.rflags &= TST_RFLAGS_STATUS_MASK;
  ctx.rflags |= ERI_TRACE_FLAG_MASK;
  ctx.rsp = (uint64_t) user_stack + sizeof user_stack;
  if (syscall)
    {
      ctx.rax = __NR_gettid;
      ctx.rip = (uint64_t) tst_raw_syscall;
    }
  else
    ctx.rip = (uint64_t) tst_raw_sync_async;

  struct eri_sigaction sa = {
    sig_raw, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
  };
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  tst_live_entry (&ctx);

  tst_rand_fill (rand, stack, sizeof stack);
  tst_rand_fill (rand, sig_stack, ERI_LIVE_SIG_STACK_SIZE);

  uint8_t entry_buf[ERI_LIVE_THREAD_ENTRY_SIZE];
  entry = tst_init_live_thread_entry (rand, entry_buf,
				      stack, sizeof stack, sig_stack);

  struct eri_stack st = { (uint64_t) sig_stack, 0, ERI_LIVE_SIG_STACK_SIZE };
  ERI_ASSERT_SYSCALL (sigaltstack, &st, 0);

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_GS, entry);
  entry->tst_skip_ctf = 1;

  if (syscall)
    {
      ctx.rax = __NR_restart_syscall; /* always return EINTR */
      ctx.rip = (uint64_t) tst_syscall;
    }
  else
    ctx.rip = (uint64_t) tst_sync_async;

  sa.act = tst_sig_step_int_trigger,
  sa.flags |= ERI_SA_ONSTACK;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  tst_live_entry (&ctx);

  eri_tst_live_assert_thread_entry (entry);
}

uint64_t
tst_main (void)
{
  struct tst_rand rand;
  tst_rand_seed (&rand, ERI_ASSERT_SYSCALL_RES (getpid));

  eri_assert_printf ("[tst] syscall = 1 restart_no_handler = 1\n");
  syscall = 1;
  restart_no_handler = 1;
  tst (&rand);
  eri_assert (triggered == 1);
  triggered = 0;

  eri_assert_printf ("[tst] syscall = 1 restart_no_handler = 0\n");
  restart_no_handler = 0;
  tst (&rand);
  eri_assert (triggered == 2);
  triggered = 0;

  eri_assert_printf ("[tst] syscall = 0\n");
  syscall = 0;
  tst (&rand);
  eri_assert (triggered == 1);

  return 0;
}
