#include "tst/tst-live-entry-common.h"

#include "lib/tst/tst-util.h"

#include "live-entry.h"
#include "lib/syscall.h"

struct eri_live_thread_entry *
tst_init_live_thread_entry (struct tst_rand *rand,
			    uint8_t *buf, uint8_t *stack, uint64_t stack_size,
			    uint8_t *sig_stack)
{
  if (rand) tst_rand_fill (rand, buf, ERI_LIVE_THREAD_ENTRY_SIZE);
  struct eri_live_thread_entry *entry = (void *) buf;
  if (rand) tst_rand_fill (rand, stack, stack_size);
  if (rand) tst_rand_fill (rand, sig_stack, ERI_LIVE_SIG_STACK_SIZE);

  eri_live_init_thread_entry (entry, entry,
		(uint64_t) stack + stack_size, stack_size, sig_stack);
  return entry;
}

struct eri_live_thread_entry *
tst_init_start_live_thread_entry (struct tst_rand *rand, uint8_t *buf,
				  uint8_t *stack, uint64_t stack_size,
				  uint8_t *sig_stack)
{
  struct eri_live_thread_entry *entry = tst_init_live_thread_entry (
				rand, buf, stack, stack_size, sig_stack);

  struct eri_stack st = { (uint64_t) sig_stack, 0, ERI_LIVE_SIG_STACK_SIZE };
  ERI_ASSERT_SYSCALL (sigaltstack, &st, 0);

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_GS, entry);

  return entry;
}

int32_t eri_live_get_sig_stack (struct eri_live_entry_sig_stack_info *info,
				void *thread) __attribute__ ((weak));

int32_t
eri_live_get_sig_stack (struct eri_live_entry_sig_stack_info *info,
			void *thread)
{
  return 0;
}

void
tst_assert_mctx_eq (struct eri_mcontext *ctx1,
		    struct eri_mcontext *ctx2, uint32_t flags)
{
#define CHECK_ASSERT_EQ(R, r) \
  do {									\
    if (! (flags & _ERS_PASTE (TST_MEQ_N, R)))				\
      eri_assert (ctx1->r == ctx2->r);					\
  } while (0)

  CHECK_ASSERT_EQ(R8, r8);
  CHECK_ASSERT_EQ(R9, r9);
  CHECK_ASSERT_EQ(R10, r10);
  CHECK_ASSERT_EQ(R11, r11);
  CHECK_ASSERT_EQ(R12, r12);
  CHECK_ASSERT_EQ(R13, r13);
  CHECK_ASSERT_EQ(R14, r14);
  CHECK_ASSERT_EQ(R15, r15);
  CHECK_ASSERT_EQ(RDI, rdi);
  CHECK_ASSERT_EQ(RSI, rsi);
  CHECK_ASSERT_EQ(RBP, rbp);
  CHECK_ASSERT_EQ(RBX, rbx);
  CHECK_ASSERT_EQ(RDX, rdx);
  CHECK_ASSERT_EQ(RAX, rax);
  CHECK_ASSERT_EQ(RCX, rcx);
  CHECK_ASSERT_EQ(RSP, rsp);
  CHECK_ASSERT_EQ(RIP, rip);
  if (! (flags & TST_MEQ_NRFLAGS))
    eri_assert ((ctx1->rflags & ~0x10000) == (ctx2->rflags & ~0x10000));
}

void
tst_block_all_signals (void)
{
  struct eri_sigset set;
  eri_sigfillset (&set);
  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK, &set,
		      0, ERI_SIG_SETSIZE);
}

void
tst_unblock_all_signals (void)
{
  struct eri_sigset set;
  eri_sigemptyset (&set);
  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK, &set,
		      0, ERI_SIG_SETSIZE);
}

static void
sig_record (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  struct tst_rip_record *recs = *(void **) ctx->stack.sp;
  struct tst_rip_record *rec;
  for (rec = recs; rec->rip; ++rec)
    if (ctx->mctx.rip == rec->rip) *rec->ctx = ctx->mctx;
}

void
tst_sig_record_mctxs (struct tst_context *ctx,
		      struct tst_rip_record *recs)
{
  uint64_t rflags = ctx->rflags;
  ctx->rflags |= ERI_TRACE_FLAG_MASK;

  uint8_t sig_stack[8192];
  *(struct tst_rip_record **) sig_stack = recs;

  struct eri_stack st = { (uint64_t) sig_stack, 0, sizeof sig_stack };
  struct eri_stack old_st;
  ERI_ASSERT_SYSCALL (sigaltstack, &st, &old_st);

  struct eri_sigaction sa = {
    sig_record, ERI_SA_RESTORER | ERI_SA_SIGINFO | ERI_SA_ONSTACK,
    eri_sigreturn
  };
  struct eri_sigaction old_sa;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP,
		      &sa, &old_sa, ERI_SIG_SETSIZE);

  tst_live_entry (ctx);

  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &old_sa, 0, ERI_SIG_SETSIZE);
  ERI_ASSERT_SYSCALL (sigaltstack, &old_st, 0);

  ctx->rflags = rflags;
}

int32_t
tst_sig_step_int_check (struct tst_step *step, uint64_t rip,
			uint64_t enter, uint64_t leave)
{
  if (step->stepping)
    {
      if (step->trigger_steps == step->trigger)
	{
	  step->stepping = 0;
	  return ERI_SIGINT;
	}

      ++step->trigger_steps;
    }

  if (rip == enter) step->stepping = 1;
  if (rip == leave) step->stepping = 0;

  return 0;
}
