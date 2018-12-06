#include "tst-live-entry.h"

#include "live.h"

#include "lib/syscall.h"
#include "public/comm.h"

#define EXL(l)	extern uint8_t _ERS_PASTE (T, l)[];

#define T	r
LS (EXL)
#undef T
#define T	x
LS (EXL)

uint64_t *vvv;
void *uuu;

const char *d = "!\n";
const char *dd = "!!\n";
const char *ddd = "!!!\n";

struct addr
{
  uint8_t *rl;
  uint8_t *xl;
  struct eri_mcontext ctx;
  uint64_t steps;
};

#define ADDR(l)		{ _ERS_PASTE (r, l), _ERS_PASTE (x, l) },
struct addr addrs[] = { LS (ADDR) };

static void
sig_raw_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  static uint16_t c;

  eri_assert ((uint64_t) addrs[c].rl == ctx->mctx.rip);
  addrs[c].ctx = ctx->mctx;
  ++c;
}

static uint8_t stk[ERI_STACK_SIZE];

static uint64_t val;

void
setup (void)
{
  vvv = &val;
  uuu = _ERS_PASTE (r, L (IJMP));

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
  TH (template).top16 = (uint64_t) stk + ERI_STACK_SIZE - 16;
  TH (template).rsp = (uint64_t) stk + ERI_STACK_SIZE;

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
sig_x_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  ++addrs[cinst].steps;

  if ((uint64_t) addrs[cinst].xl == ctx->mctx.rip)
    {
      uint8_t s = cinst < ISYS ? EQ_ORCX : 0;
      assert_eq (&addrs[cinst].ctx, &ctx->mctx, s);
      addrs[cinst].ctx = ctx->mctx;
      if (cinst > ISYS && cinst < IMJMP)
	eri_assert (addrs[cinst].ctx.rcx == addrs[ISYS].ctx.rcx);
      else if (cinst >= IMJMP)
	eri_assert (addrs[cinst].ctx.rcx == (uint64_t) uuu);
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
#ifdef TT_XCHG
	|| cinst == IXCHG
#endif
#ifdef TT_SYSCALL
	|| cinst == ISYS
#endif
#ifdef TT_SYNC
	|| cinst == IJMP
#endif
	;
}

int32_t
sig_sig_step (int32_t signum, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  ERI_ASSERT_SYSCALL (write, 1, ddd, 4);
  ++sig_steps;

#ifdef TT_XCHG
  if (cinst == IXCHG
      && ctx->mctx.rip == (uint64_t) eri_tst_live_thread_xchg_complete_start
      && retry == 1)
    retry = 0;
#endif
#ifdef TT_SYSCALL
  if (cinst == ISYS
      && ctx->mctx.rip == (uint64_t) eri_tst_live_thread_syscall_complete_start
      && retry == 1)
    retry = 0;
#endif
#ifdef TT_SYNC
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

static void
assert_x (void)
{
  eri_assert (TH (template).common.mark == 0);
  eri_assert (TH (template).common.dir == 0);
  eri_assert (TH (template).rsp == (uint64_t) stk + ERI_STACK_SIZE);
  eri_assert (TH (template).restart == 0);
}

static uint64_t sigact_sig_step_num;

static void
sigact_sig_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  ERI_ASSERT_SYSCALL (write, 1, d, 2);
  ++sigact_sig_step_num;

  assert_x ();
  assert_eq (&addrs[cinst - !! retry].ctx, &ctx->mctx, EQ_ORCX | EQ_ORIP);
  if (! retry)
    next_sig_step_inst ();
}

static void
sigact_trap (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  assert_x ();
  assert_eq (&addrs[cinst].ctx, &ctx->mctx, EQ_ORCX | EQ_ORIP);
  ++cinst;
}

static void
sigact_segv (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (sig == ERI_SIGSEGV && cinst == 0)
    {
      assert_x ();
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
      assert_x ();
      uint64_t rflags = ctx->mctx.rflags;
      ctx->mctx.rflags &= ~0x10000;
      assert_eq (&addrs[IMJMP].ctx, &ctx->mctx, 0);
      ctx->mctx.rflags = rflags;
      eri_assert (ctx->mctx.rcx == 0);
      eri_assert (ctx->mctx.rip == 0);

      ++cinst;
      ctx->mctx.rcx = (uint64_t) _ERS_PASTE (x, L (IJMP));
      ctx->mctx.rip = (uint64_t) _ERS_PASTE (x, L (IMJMP));
    }
  else eri_assert (sig == ERI_SIGTRAP);
}

void *sigact;

static void
regx (void *a)
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

static uint16_t xx;
uint8_t
process (void)
{
#define XX_RAW		0
#define XX_STEP		1
#define XX_SIG_STEP	2
#define XX_TRAP		3
#define XX_SEGV		4

  static uint64_t max_steps;
  if (xx == XX_RAW)
    {
      struct eri_sigaction sa = {
	sig_x_step, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
      };
      ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

      uuu = _ERS_PASTE (x, L (IJMP));

      ERI_ASSERT_SYSCALL (write, 1, dd, 3);
      ++xx;
      return 1;
    }
  else if (xx == XX_STEP)
    {
      cinst = 0;

      regx (sig_x_sig_step);

      uint8_t c;
      for (c = 0; c < eri_length_of (addrs); ++c)
	if (addrs[c].steps > max_steps) max_steps = addrs[c].steps;

      sigact = sigact_sig_step;

      ERI_ASSERT_SYSCALL (write, 1, dd, 3);
      ++xx;
      return 1;
    }
  else if (xx == XX_SIG_STEP)
    {
      ERI_ASSERT_SYSCALL (write, 1, dd, 3);

      cinst = 0;
      sig_steps = 0;

      if (ignore_steps < max_steps)
        eri_assert (sigact_sig_step_num);
      else if (ignore_steps == max_steps)
        eri_assert (! sigact_sig_step_num);

      ++ignore_steps;
      sigact_sig_step_num = 0;

      if (ignore_steps > max_steps)
	{
	  TH (template).tst_skip_ctf = 0;
	  regx (eri_live_sigaction);
	  sigact = sigact_trap;
	  ++xx;
	}
      return 1;
    }
  else if (xx == XX_TRAP)
    {
      eri_assert (cinst == eri_length_of (addrs));

      regx (eri_live_sigaction);

      vvv = 0;
      uuu = 0;
      cinst = 0;
      sigact = sigact_segv;
      ++xx;
      return 1;
    }
  return 0;
}
