#include "tst/tst-live-entry.h"

#include "live.h"

#include "lib/syscall.h"
#include "lib/printf.h"
#include "public/comm.h"

#define EXTERN_LABEL(label)	extern uint8_t SUFFIX (label)[];

#define SUF	_raw
LABELS (EXTERN_LABEL)
#undef SUF
#define SUF
LABELS (EXTERN_LABEL)

uint64_t *xchg_mem_b;
uint64_t *xchg_mem_w;
uint64_t *xchg_mem_l;
uint64_t *xchg_mem_q;
uint64_t *inc_mem;
void *jmp_mem;

struct addr
{
  uint8_t *raw_label;
  uint8_t *label;
  struct eri_mcontext ctx;
  uint64_t steps;
};

#define ADDR(label)		{ _ERS_PASTE (label, _raw), label },
struct addr addrs[] = { LABELS (ADDR) };

static void
sig_raw_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  static uint16_t c;

  eri_assert ((uint64_t) addrs[c].raw_label == ctx->mctx.rip);
  addrs[c].ctx = ctx->mctx;
  ++c;
}

static uint8_t stk[ERI_STACK_SIZE];

static uint64_t xchg_val = 0x123456789abcdef0;
static uint64_t inc_val = 0xffffffffffffffff;

void
setup (void)
{
  xchg_mem_b = &xchg_val;
  xchg_mem_w = &xchg_val;
  xchg_mem_l = &xchg_val;
  xchg_mem_q = &xchg_val;
  inc_mem = &inc_val;
  jmp_mem = _ERS_PASTE (LABEL (IJMP), _raw);

  struct eri_sigaction sa = {
    sig_raw_step, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
  };
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  extern struct eri_sigset eri_live_sigempty; // TODO
  eri_sigaddset (&eri_live_sigempty, ERI_SIGSEGV);

#define TH(i)	_ERS_PASTE (eri_live_thread_, i)
#define TT(i)	TH (_ERS_PASTE (template_, i))

  uint64_t sz16 = eri_round_up (sizeof (struct eri_live_thread), 16);
#define SET_TH_RELA(t, f, e) \
  do {									\
    (t)->f = (uint64_t) (t) + sz16 + (e - TT (text));			\
  } while (0)

  SET_TH_RELA (&TH (template), common.thread_entry, TT (entry));
  TH (template).entry = (uint64_t) eri_live_entry;
  SET_TH_RELA (&TH (template), common.thread_entry, TT (entry));

  TH (template).top = (uint64_t) stk + ERI_STACK_SIZE;
  TH (template).top_saved = TH (template).top - ERI_LIVE_ENTRY_SAVED_REG_SIZE;
  TH (template).rsp = TH (template).top;

  SET_TH_RELA (&TH (template), thread_internal_cont, TT (internal_cont));
  SET_TH_RELA (&TH (template), thread_external_cont, TT (external_cont));
  SET_TH_RELA (&TH (template), thread_cont_end, TT (cont_end));

  SET_TH_RELA (&TH (template), thread_ret, TT (ret));
  SET_TH_RELA (&TH (template), thread_ret_end, TT (ret_end));

  SET_TH_RELA (&TH (template), thread_resume, TT (resume));
  SET_TH_RELA (&TH (template), thread_resume_ret, TT (resume_ret));

  TH (template).resume_ret = (uint64_t) eri_live_resume_ret;

  TH (template).tst_skip_ctf = 1;

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_GS, &TH (template));
}

#define EQ_NR8		(1 << 1)
#define EQ_NR9		(1 << 2)
#define EQ_NR10		(1 << 3)
#define EQ_NR11		(1 << 4)
#define EQ_NR12		(1 << 5)
#define EQ_NR13		(1 << 6)
#define EQ_NR14		(1 << 7)
#define EQ_NR15		(1 << 8)
#define EQ_NRDI		(1 << 9)
#define EQ_NRSI		(1 << 10)
#define EQ_NRBP		(1 << 11)
#define EQ_NRBX		(1 << 12)
#define EQ_NRDX		(1 << 13)
#define EQ_NRAX		(1 << 14)
#define EQ_NRCX		(1 << 15)
#define EQ_NRSP		(1 << 16)
#define EQ_NRIP		(1 << 17)
#define EQ_NRFLAGS	(1 << 18)

static void
assert_eq (struct eri_mcontext *c1, struct eri_mcontext *c2, uint32_t s)
{
#define CHECK_ASSERT_EQ(R, r) \
  do {									\
    if (! (s & _ERS_PASTE (EQ_N, R))) eri_assert (c1->r == c2->r);	\
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
  CHECK_ASSERT_EQ(RFLAGS, rflags);
}

static uint16_t cinst;

static void
assert_thread (void)
{
  eri_assert (TH (template).common.mark == 0);
  eri_assert (TH (template).common.dir == 0);
  eri_assert (TH (template).rsp == (uint64_t) stk + ERI_STACK_SIZE);
  eri_assert (TH (template).restart == 0);
}

static void
sig_x_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  ++addrs[cinst].steps;

  if ((uint64_t) addrs[cinst].label == ctx->mctx.rip)
    {
      assert_thread ();
      uint32_t s = cinst < ISYS ? EQ_NRIP : EQ_NRIP | EQ_NRCX;
      assert_eq (&addrs[cinst].ctx, &ctx->mctx, s);
      addrs[cinst].ctx = ctx->mctx;
      if (cinst > ISYS && cinst < IMJMP)
	eri_assert (addrs[cinst].ctx.rcx == addrs[ISYS].ctx.rcx);
      else if (cinst >= IMJMP)
	eri_assert (addrs[cinst].ctx.rcx == (uint64_t) jmp_mem);
      ++cinst;
    }
}

uint64_t ignore_steps;
static uint64_t sig_steps;

static uint64_t retry;

static void
next_sig_step_inst (void)
{
  sig_steps = 0;
  ++cinst;

  retry = 0
#define ATOMIC_CINST_P(op) \
  (cinst == _ERS_PASTE (op, B) || cinst == _ERS_PASTE (op, W)		\
   || cinst == _ERS_PASTE (op, L) || cinst == _ERS_PASTE (op, Q))
#ifdef TST_XCHG
	|| ATOMIC_CINST_P (IXCHG)
#endif
#ifdef TST_INC
	|| ATOMIC_CINST_P (IINC)
#endif
#ifdef TST_SYSCALL
	|| cinst == ISYS
#endif
#ifdef TST_SYNC
	|| cinst == IJMP
#endif
	;
}

int32_t
sig_sig_step (int32_t signum, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  ++sig_steps;
  eri_assert_printf ("sig_sig_step %lu\n", sig_steps);

#define CHECK_CLEAR_RETRY(op, addr) \
  do {									\
    if (cinst == (op) && ctx->mctx.rip == (addr) && retry == 1)		\
      retry = 0;							\
  } while (0)

#define CHECK_CLEAR_ATOMIC_RETRY(op, label) \
  do {									\
    CHECK_CLEAR_RETRY (_ERS_PASTE (op, B),				\
      (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (b, label));	\
    CHECK_CLEAR_RETRY (_ERS_PASTE (op, W),				\
      (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (w, label));	\
    CHECK_CLEAR_RETRY (_ERS_PASTE (op, L),				\
      (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (l, label));	\
    CHECK_CLEAR_RETRY (_ERS_PASTE (op, Q),				\
      (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (q, label));	\
  } while (0)

#ifdef TST_XCHG
  CHECK_CLEAR_ATOMIC_RETRY (IXCHG, xchg);
#endif
#ifdef TST_INC
  CHECK_CLEAR_ATOMIC_RETRY (IINC, inc);
#endif
#ifdef TST_SYSCALL
  CHECK_CLEAR_RETRY (ISYS,
    (uint64_t) ERI_TST_LIVE_COMPLETE_START_NAME (syscall));
#endif
#ifdef TST_SYNC
  CHECK_CLEAR_RETRY (IJMP, (uint64_t) addrs[IJMP].label);
#endif

  if (sig_steps > ignore_steps && retry < 2)
    {
      if (retry == 1)
	{
	  sig_steps = 0;
	  retry = 2;
	}
      return ERI_SIGINT;
    }

  if (sig_steps == addrs[cinst].steps)
    next_sig_step_inst ();

  return 0;
}

void sig_x_sig_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx);

static uint64_t sigact_sig_step_num;

static void
sigact_sig_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_assert_printf ("sigact_sig_step\n");
  ++sigact_sig_step_num;

  assert_thread ();
  assert_eq (&addrs[cinst - !! retry].ctx, &ctx->mctx, 0);
  if (! retry)
    next_sig_step_inst ();
}

static void
sigact_trap (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  assert_thread ();
  assert_eq (&addrs[cinst].ctx, &ctx->mctx, 0);
  ++cinst;
}

static void
sigact_segv (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (sig == ERI_SIGSEGV && cinst == 0)
    {
      assert_thread ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000;
      eri_assert (ctx->mctx.rcx == 0);
      eri_assert (ctx->mctx.rdi == 0);
      ctx->mctx.rcx = (uint64_t) &xchg_val;
      assert_eq (&addrs[INOP].ctx, &ctx->mctx, EQ_NRDI);
      ctx->mctx.rflags = rflags;
      ++cinst;
    }
  else if (sig == ERI_SIGSEGV && cinst == 1)
    {
      assert_thread ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000;
      eri_assert (ctx->mctx.rdi == 0);
      ctx->mctx.rdi = (uint64_t) &inc_val;
      assert_eq (&addrs[IXCHGQ].ctx, &ctx->mctx, 0);
      ctx->mctx.rflags = rflags;
      ++cinst;
    }
  else if (sig == ERI_SIGSEGV && cinst == 2)
    {
      assert_thread ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000;
      assert_eq (&addrs[IMJMP].ctx, &ctx->mctx, EQ_NRCX | EQ_NRIP);
      ctx->mctx.rflags = rflags;
      eri_assert (ctx->mctx.rcx == 0);
      eri_assert (ctx->mctx.rip == 0);

      ++cinst;
      ctx->mctx.rcx = (uint64_t) LABEL (IJMP);
      ctx->mctx.rip = (uint64_t) LABEL (IMJMP);
    }
  else eri_assert (sig == ERI_SIGTRAP);
}

void *sigact;

static void
reg_sigaction (void *a)
{
  static uint8_t ss[ERI_SIG_STACK_SIZE];
  *(struct eri_live_thread **) ss = &TH (template);
  struct eri_stack st = { ss, 0, sizeof ss };
  ERI_ASSERT_SYSCALL (sigaltstack, &st, 0);

  struct eri_sigaction sa = {
    a, ERI_SA_RESTORER | ERI_SA_SIGINFO | ERI_SA_ONSTACK, eri_sigreturn
  };
  eri_sigfillset (&sa.mask);
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGSEGV, &sa, 0, ERI_SIG_SETSIZE);
}

static uint16_t proc;

uint8_t
process (void)
{
#define PROC_RAW		0
#define PROC_STEP		1
#define PROC_SIG_STEP		2
#define PROC_TRAP		3
#define PROC_SEGV		4

  eri_assert_printf ("process: %u\n", proc);
  static uint64_t max_steps;
  static uint64_t final_inc_val;
  if (proc == PROC_RAW)
    {
      struct eri_sigaction sa = {
	sig_x_step, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
      };
      ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

      jmp_mem = LABEL (IJMP);

      xchg_val = 0x123456789abcdef0;
      inc_val = 0xffffffffffffffff;
      ++proc;
      return 1;
    }
  else if (proc == PROC_STEP)
    {
      cinst = 0;

      reg_sigaction (sig_x_sig_step);

      uint8_t c;
      for (c = 0; c < eri_length_of (addrs); ++c)
	if (addrs[c].steps > max_steps) max_steps = addrs[c].steps;

      sigact = sigact_sig_step;

      final_inc_val = inc_val;
      xchg_val = 0x123456789abcdef0;
      inc_val = 0xffffffffffffffff;
      ++proc;
      return 1;
    }
  else if (proc == PROC_SIG_STEP)
    {
      cinst = 0;
      sig_steps = 0;

      if (ignore_steps < max_steps)
        eri_assert (sigact_sig_step_num);
      else if (ignore_steps == max_steps)
        eri_assert (! sigact_sig_step_num);

      ++ignore_steps;
      sigact_sig_step_num = 0;

      eri_assert (final_inc_val == inc_val);
      xchg_val = 0x123456789abcdef0;
      inc_val = 0xffffffffffffffff;
      if (ignore_steps > max_steps)
	{
	  TH (template).tst_skip_ctf = 0;
	  reg_sigaction (eri_live_sigaction);
	  sigact = sigact_trap;
	  ++proc;
	}
      return 1;
    }
  else if (proc == PROC_TRAP)
    {
      eri_assert (cinst == eri_length_of (addrs));

      reg_sigaction (eri_live_sigaction);

      eri_assert (final_inc_val == inc_val);
      xchg_val = 0x123456789abcdef0;
      inc_val = 0xffffffffffffffff;
      xchg_mem_b = 0;
      inc_mem = 0;
      jmp_mem = 0;
      cinst = 0;
      sigact = sigact_segv;
      ++proc;
      return 1;
    }
  else
    {
      eri_assert (cinst == 3);
      eri_assert (final_inc_val == inc_val);
    }
  return 0;
}
