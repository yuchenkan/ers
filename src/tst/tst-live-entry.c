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
uint64_t *stor_mem;
uint64_t *load_mem;
uint64_t *cmpxchg_mem;
uint64_t *cmp_mem;
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

#define STACK_SIZE	(2 * 1024 * 1024)
static uint8_t stk[STACK_SIZE];
#define TBUF_SIZE	512
static uint8_t thread[sizeof (struct eri_live_thread) + 16 + TBUF_SIZE];
#define thread		(*(struct eri_live_thread *) thread)

static uint64_t xchg_val = 0x123456789abcdef0;
static uint64_t inc_val = 0xffffffffffffffff;
static uint64_t stor_val = 0x123456789abcdef0;
static uint64_t load_val = 0x123456789a;
static uint64_t cmpxchg_val = 0;
static uint64_t cmp_val = 0;

void
setup (void)
{
  xchg_mem_b = &xchg_val;
  xchg_mem_w = &xchg_val;
  xchg_mem_l = &xchg_val;
  xchg_mem_q = &xchg_val;
  inc_mem = &inc_val;
  stor_mem = &stor_val;
  load_mem = &load_val;
  cmpxchg_mem = &cmpxchg_val;
  cmp_mem = &cmp_val;
  jmp_mem = _ERS_PASTE (LABEL (IJMP), _raw);

  struct eri_sigaction sa = {
    sig_raw_step, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
  };
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  extern struct eri_sigset eri_live_sigempty; // TODO
  eri_sigaddset (&eri_live_sigempty, ERI_SIGSEGV);

  extern struct eri_live_internal eri_live_internal;
  static uint64_t atomic_mem_table;
  eri_live_internal.atomic_mem_table = &atomic_mem_table;

  eri_assert (TBUF_SIZE >= eri_live_thread_text_end - eri_live_thread_text);
  eri_live_init_thread (&thread, 0, (uint64_t) stk + STACK_SIZE, STACK_SIZE);

  thread.tst_skip_ctf = 1;

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_GS, &thread);
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
  eri_assert (thread.common.mark == 0);
  eri_assert (thread.common.dir == 0);
  eri_assert (thread.rsp == (uint64_t) stk + STACK_SIZE);
  eri_assert (thread.fix_restart == 0);
  eri_assert (thread.restart == 0);
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
#ifdef TST_STOR
	|| ATOMIC_CINST_P (ISTOR)
#endif
#ifdef TST_LOAD
	|| cinst == ILOADQ
#endif
#ifdef TST_CMPXCHG
	|| cinst == ICMPXCHGQ_EQ || cinst == ICMPXCHGQ_NE
#endif
#ifdef TST_CMP
	|| cinst == ICMPQ_EQ || cinst == ICMPQ_NE
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
  eri_assert ((ctx->mctx.rflags & 0x400) == 0);
  ++sig_steps;
  eri_assert_printf ("sig_sig_step %u %lu %lx\n", cinst, sig_steps, ctx->mctx.rip);

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
#ifdef TST_STOR
  CHECK_CLEAR_ATOMIC_RETRY (ISTOR, stor);
#endif
#ifdef TST_LOAD
  CHECK_CLEAR_RETRY (ILOADQ,
    (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (q, load));
#endif
#ifdef TST_CMPXCHG
  CHECK_CLEAR_RETRY (ICMPXCHGQ_EQ,
    (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (q, cmpxchg));
  CHECK_CLEAR_RETRY (ICMPXCHGQ_NE,
    (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (q, cmpxchg));
#endif
#ifdef TST_CMP
  CHECK_CLEAR_RETRY (ICMPQ_EQ,
    (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (q, load));
  CHECK_CLEAR_RETRY (ICMPQ_NE,
    (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (q, load));
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
  eri_assert (ctx->link == 0);
  assert_eq (&addrs[cinst].ctx, &ctx->mctx, 0);
  ++cinst;
}

static void
sigact_segv (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (sig == ERI_SIGSEGV && cinst == 0)
    {
      /* XCHGB  */
      assert_thread ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000; /* TODO */
      eri_assert (ctx->mctx.rcx == 0);
      ctx->mctx.rcx = (uint64_t) &xchg_val;
      eri_assert (ctx->mctx.rdi == 0);
      eri_assert (ctx->mctx.rsi == 0);
      eri_assert (ctx->mctx.r8 == 0);
      eri_assert (ctx->mctx.r9 == 0);
      eri_assert (ctx->mctx.r10 == 0);
      assert_eq (&addrs[IXCHGB - 1].ctx, &ctx->mctx,
		 EQ_NRDI | EQ_NRSI | EQ_NR8 | EQ_NR9 | EQ_NR10);
      ctx->mctx.rflags = rflags;
      ++cinst;
    }
  else if (sig == ERI_SIGSEGV && cinst == 1)
    {
      /* INCB  */
      assert_thread ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000;
      eri_assert (ctx->mctx.rdi == 0);
      ctx->mctx.rdi = (uint64_t) &inc_val;
      eri_assert (ctx->mctx.rsi == 0);
      eri_assert (ctx->mctx.r8 == 0);
      eri_assert (ctx->mctx.r9 == 0);
      eri_assert (ctx->mctx.r10 == 0);
      assert_eq (&addrs[IINCB - 1].ctx, &ctx->mctx,
		 EQ_NRSI | EQ_NR8 | EQ_NR9 | EQ_NR10);
      ctx->mctx.rflags = rflags;
      ++cinst;
    }
  else if (sig == ERI_SIGSEGV && cinst == 2)
    {
      /* STORQ  */
      assert_thread ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000;
      eri_assert (ctx->mctx.rsi == 0);
      ctx->mctx.rsi = (uint64_t) &stor_val;
      eri_assert (ctx->mctx.r8 == 0);
      eri_assert (ctx->mctx.r9 == 0);
      eri_assert (ctx->mctx.r10 == 0);
      assert_eq (&addrs[ISTORQ - 1].ctx, &ctx->mctx, EQ_NR8 | EQ_NR9 | EQ_NR10);
      ctx->mctx.rflags = rflags;
      ++cinst;
    }
  else if (sig == ERI_SIGSEGV && cinst == 3)
    {
      /* LOADQ  */
      assert_thread ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000;
      eri_assert (ctx->mctx.r8 == 0);
      ctx->mctx.r8 = (uint64_t) &load_val;
      eri_assert (ctx->mctx.r9 == 0);
      eri_assert (ctx->mctx.r10 == 0);
      assert_eq (&addrs[ILOADQ - 1].ctx, &ctx->mctx, EQ_NR9 | EQ_NR10);
      ctx->mctx.rflags = rflags;
      ++cinst;
    }
  else if (sig == ERI_SIGSEGV && cinst == 4)
    {
      /* CMPXCHGQ  */
      assert_thread ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000;
      eri_assert (ctx->mctx.r9 == 0);
      ctx->mctx.r9 = (uint64_t) &cmpxchg_val;
      eri_assert (ctx->mctx.r10 == 0);
      assert_eq (&addrs[ICMPXCHGQ_EQ - 1].ctx, &ctx->mctx, EQ_NR10);
      ctx->mctx.rflags = rflags;
      ++cinst;
    }
  else if (sig == ERI_SIGSEGV && cinst == 5)
    {
      /* CMPQ  */
      assert_thread ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000;
      eri_assert (ctx->mctx.r10 == 0);
      ctx->mctx.r10 = (uint64_t) &cmp_val;
      assert_eq (&addrs[ICMPQ_EQ - 1].ctx, &ctx->mctx, 0);
      ctx->mctx.rflags = rflags;
      ++cinst;
    }
  else if (sig == ERI_SIGSEGV && cinst == 6)
    {
      /* JMP  */
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
  *(struct eri_live_thread **) ss = &thread;
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
  static uint64_t final_cmpxchg_val;
  if (proc == PROC_RAW)
    {
      struct eri_sigaction sa = {
	sig_x_step, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
      };
      ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

      jmp_mem = LABEL (IJMP);

      final_inc_val = inc_val;
      final_cmpxchg_val = cmpxchg_val;
      xchg_val = 0x123456789abcdef0;
      inc_val = 0xffffffffffffffff;
      stor_val = 0x123456789abcdef0;
      cmpxchg_val = 0;
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

      eri_assert (final_inc_val == inc_val);
      eri_assert (load_val == 0x123456789a);
      eri_assert (final_cmpxchg_val == cmpxchg_val);
      xchg_val = 0x123456789abcdef0;
      inc_val = 0xffffffffffffffff;
      stor_val = 0x123456789abcdef0;
      cmpxchg_val = 0;
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
      eri_assert (load_val == 0x123456789a);
      eri_assert (final_cmpxchg_val == cmpxchg_val);
      xchg_val = 0x123456789abcdef0;
      inc_val = 0xffffffffffffffff;
      stor_val = 0x123456789abcdef0;
      cmpxchg_val = 0;
      if (ignore_steps > max_steps)
	{
	  thread.tst_skip_ctf = 0;
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
      eri_assert (load_val == 0x123456789a);
      eri_assert (final_cmpxchg_val == cmpxchg_val);
      xchg_val = 0x123456789abcdef0;
      inc_val = 0xffffffffffffffff;
      stor_val = 0x123456789abcdef0;
      cmpxchg_val = 0;
      xchg_mem_b = 0;
      inc_mem = 0;
      stor_mem = 0;
      load_mem = 0;
      cmpxchg_mem = 0;
      cmp_mem = 0;
      jmp_mem = 0;
      cinst = 0;
      sigact = sigact_segv;
      ++proc;
      return 1;
    }
  else
    {
      reg_sigaction (0);

      eri_assert (cinst == 7);
      eri_assert (final_inc_val == inc_val);
      eri_assert (load_val == 0x123456789a);
      eri_assert (final_cmpxchg_val == cmpxchg_val);
    }
  return 0;
}
