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
void *jmp_mem;

struct addr
{
  uint8_t *rl;
  uint8_t *xl;
  struct eri_mcontext ctx;
  uint64_t steps;
};

#define ADDR(label)		{ _ERS_PASTE (label, _raw), label },
struct addr addrs[] = { LABELS (ADDR) };

static void
sig_raw_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  static uint16_t c;

  eri_assert ((uint64_t) addrs[c].rl == ctx->mctx.rip);
  addrs[c].ctx = ctx->mctx;
  ++c;
}

static uint8_t stk[ERI_STACK_SIZE];

static uint64_t val = 0x123456789abcdef0;

void
setup (void)
{
  xchg_mem_b = &val;
  xchg_mem_w = &val;
  xchg_mem_l = &val;
  xchg_mem_q = &val;
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

#define EQ_ORCX 	1
#define EQ_ORIP		2

static void
assert_eq (struct eri_mcontext *c1, struct eri_mcontext *c2, uint8_t s)
{
  eri_assert (c1->r8 == c2->r8);
  eri_assert (c1->r9 == c2->r9);
  eri_assert (c1->r10 == c2->r10);
  eri_assert (c1->r11 == c2->r11);
  eri_assert (c1->r12 == c2->r12);
  eri_assert (c1->r13 == c2->r13);
  eri_assert (c1->r14 == c2->r14);
  eri_assert (c1->r15 == c2->r15);
  eri_assert (c1->rdi == c2->rdi);
  eri_assert (c1->rsi == c2->rsi);
  eri_assert (c1->rbp == c2->rbp);
  eri_assert (c1->rbx == c2->rbx);
  eri_assert (c1->rdx == c2->rdx);
  eri_assert (c1->rax == c2->rax);
  if (s & EQ_ORCX) eri_assert (c1->rcx == c2->rcx);
  eri_assert (c1->rsp == c2->rsp);
  if (s & EQ_ORIP) eri_assert (c1->rip == c2->rip);
  eri_assert (c1->rflags == c2->rflags);
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

  if ((uint64_t) addrs[cinst].xl == ctx->mctx.rip)
    {
      assert_thread ();
      uint8_t s = cinst < ISYS ? EQ_ORCX : 0;
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
#ifdef TST_XCHG
	|| cinst == IXCHGB
	|| cinst == IXCHGL
	|| cinst == IXCHGW
	|| cinst == IXCHGQ
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

#ifdef TST_XCHG
  if (cinst == IXCHGB
      && ctx->mctx.rip
	== (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (b, xchg)
      && retry == 1)
    retry = 0;
  if (cinst == IXCHGW
      && ctx->mctx.rip
	== (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (w, xchg)
      && retry == 1)
    retry = 0;
  if (cinst == IXCHGL
      && ctx->mctx.rip
	== (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (l, xchg)
      && retry == 1)
    retry = 0;
  if (cinst == IXCHGQ
      && ctx->mctx.rip
	== (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (q, xchg)
      && retry == 1)
    retry = 0;
#endif
#ifdef TST_SYSCALL
  if (cinst == ISYS
      && ctx->mctx.rip
	== (uint64_t) ERI_TST_LIVE_COMPLETE_START_NAME (syscall)
      && retry == 1)
    retry = 0;
#endif
#ifdef TST_SYNC
  if (cinst == IJMP
      && ctx->mctx.rip == (uint64_t) addrs[IJMP].xl
      && retry == 1)
    retry = 0;
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
  assert_eq (&addrs[cinst - !! retry].ctx, &ctx->mctx, EQ_ORCX | EQ_ORIP);
  if (! retry)
    next_sig_step_inst ();
}

static void
sigact_trap (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  assert_thread ();
  assert_eq (&addrs[cinst].ctx, &ctx->mctx, EQ_ORCX | EQ_ORIP);
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
      assert_eq (&addrs[INOP].ctx, &ctx->mctx, EQ_ORIP);
      ctx->mctx.rflags = rflags;
      eri_assert (ctx->mctx.rcx == 0);
      ++cinst;

      ctx->mctx.rcx = (uint64_t) &val;
    }
  else if (sig == ERI_SIGSEGV && cinst == 1)
    {
      assert_thread ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000;
      assert_eq (&addrs[IMJMP].ctx, &ctx->mctx, 0);
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
  if (proc == PROC_RAW)
    {
      struct eri_sigaction sa = {
	sig_x_step, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
      };
      ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

      jmp_mem = LABEL (IJMP);

      val = 0x123456789abcdef0;
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

      val = 0x123456789abcdef0;
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

      val = 0x123456789abcdef0;
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

      val = 0x123456789abcdef0;
      xchg_mem_b = 0;
      jmp_mem = 0;
      cinst = 0;
      sigact = sigact_segv;
      ++proc;
      return 1;
    }
  return 0;
}
