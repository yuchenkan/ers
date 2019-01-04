#include "tst/tst-live-entry-common.h"

#include "lib/tst/tst-util.h"

#include "lib/util.h"
#include "lib/syscall.h"

#include "live-entry.h"

static uint8_t triggered;
static struct eri_mcontext before, after;

static uint8_t sig_int_triggered;

static struct eri_siginfo trap_info;

static void
sig_trap_action (int32_t sig, struct eri_siginfo *info,
		 struct eri_ucontext *ctx)
{
  eri_assert_printf ("[sig_trap_action]\n");

  eri_assert (sig == ERI_SIGTRAP);
  eri_assert (eri_memcmp (&trap_info, info, sizeof *info) == 0);
  tst_assert_mctx_eq (&before, &ctx->mctx, 0);

  eri_assert (sig_int_triggered);
}

static void
sig_int_action (int32_t sig, struct eri_siginfo *info,
		struct eri_ucontext *ctx)
{
  eri_assert_printf ("[sig_int_action]\n");

  eri_assert (sig == ERI_SIGINT);
  eri_assert (ctx->mctx.rdi == ERI_SIGTRAP);
  struct eri_siginfo *nested_info = (void *) ctx->mctx.rsi;
  struct eri_ucontext *nested_ctx = (void *) ctx->mctx.rdx;
  eri_assert (eri_memcmp (&trap_info, nested_info, sizeof *info) == 0);
  tst_assert_mctx_eq (&before, &nested_ctx->mctx, 0);

  sig_int_triggered = 1;
}

void
eri_live_get_sig_action (int32_t sig, struct eri_siginfo *info,
			 struct eri_ucontext *ctx, int32_t intr,
			 struct eri_live_entry_sig_action_info *act_info,
			 void *thread)
{
  eri_assert (act_info->type == ERI_LIVE_ENTRY_SIG_ACTION_UNKNOWN);
  eri_assert (intr == -1);

  eri_assert_printf ("[eri_live_get_sig_action] rip = %lx\n",
		     ctx->mctx.rip);

  if (ctx->mctx.rip == (uint64_t) tst_nop_enter)
    {
      eri_assert_printf ("[eri_live_get_sig_action] tst_nop_enter\n");

      eri_assert (++triggered == 1);
      trap_info = *info;

      ERI_ASSERT_SYSCALL (kill, ERI_ASSERT_SYSCALL_RES (getpid), ERI_SIGINT);

      act_info->type = ERI_LIVE_ENTRY_SIG_ACTION;
      act_info->act = (uint64_t) sig_trap_action;
      act_info->restorer = (uint64_t) eri_sigreturn;
      act_info->mask.mask_all = 0;
      eri_sigemptyset (&act_info->mask.mask);
    }
  else if (ctx->mctx.rip == (uint64_t) sig_trap_action)
    {
      eri_assert_printf ("[eri_live_get_sig_action] sig_trap_action\n");

      eri_assert (++triggered == 2);

      act_info->type = ERI_LIVE_ENTRY_SIG_ACTION;
      act_info->act = (uint64_t) sig_int_action;
      act_info->restorer = (uint64_t) eri_sigreturn;
      act_info->mask.mask_all = 0;
      eri_sigemptyset (&act_info->mask.mask);
    }
  else if (ctx->mctx.rip == (uint64_t) tst_nop_leave)
    {
      eri_assert_printf ("[eri_live_get_sig_action] tst_nop_leave\n");

      eri_assert (++triggered == 3);
      tst_assert_mctx_eq (&after, &ctx->mctx, 0);
      act_info->type = ERI_LIVE_ENTRY_SIG_NO_ACTION;
    }
  else act_info->type = ERI_LIVE_ENTRY_SIG_NO_ACTION;
}

static uint8_t stack[1024 * 1024];
static uint8_t sig_stack[ERI_LIVE_SIG_STACK_SIZE];
static struct eri_live_thread_entry *entry;

uint64_t
tst_main (void)
{
  struct tst_rand rand;
  tst_rand_seed (&rand, ERI_ASSERT_SYSCALL_RES (getpid));

  struct tst_context ctx;
  uint8_t user_stack[1024];
  tst_rand_fill_tctx (&rand, &ctx, user_stack + sizeof user_stack);
  ctx.rflags |= ERI_TRACE_FLAG_MASK;
  ctx.rip = (uint64_t) tst_nop;

  eri_assert_printf ("[tst_sig_record_nop]\n");

  tst_sig_record_nop (&ctx, &before, &after);

  uint8_t entry_buf[ERI_LIVE_THREAD_ENTRY_SIZE];
  entry = tst_init_start_live_thread_entry (
			&rand, entry_buf, stack, sizeof stack, sig_stack);

  struct eri_sigaction sa = {
    eri_live_entry_sig_action,
    ERI_SA_RESTORER | ERI_SA_SIGINFO | ERI_SA_ONSTACK, 0
  };
  eri_sigfillset (&sa.mask);
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGINT, &sa, 0, ERI_SIG_SETSIZE);

  eri_assert_printf ("[tst_live_entry]\n");

  tst_live_entry (&ctx);
  eri_tst_live_assert_thread_entry (entry);
  eri_assert (triggered == 3);

  return 0;
}
