#include "tst/tst-live-entry-basic.h"
#include "tst/tst-live-entry-common.h"

#include "live.h"
#include "live-entry.h"

#include "lib/tst/tst-util.h"

#include "lib/syscall.h"
#include "lib/printf.h"
#include "public/common.h"

#define INIT_RAW	0
#define INIT_STEP	1
#define INIT_STEP_INT	2
#define INIT_TRAP	3
#define INIT_SEGV	4

#define CHECK_CMP_ENTER	0
#define CHECK_REPEAT	1
#define CHECK_CMP	2
#define CHECK_STEP_INT	3
#define CHECK_TRAP	4
#define CHECK_SEGV	5

struct tst_case
{
  char *name;

  uint8_t (*init) (struct tst_case *, struct tst_context *, uint8_t type);
  void (*check) (struct tst_case *, struct eri_mcontext *, uint8_t type);

  uint64_t raw_enter;
  uint64_t raw_leave;

  uint64_t enter;
  uint64_t leave;

  uint64_t complete;

  void *data;

  uint64_t raw_repeat;
  uint64_t repeat;

  uint8_t repeating	: 1;
  struct tst_step step;

  uint32_t triggered;

  uint32_t steps;
  uint32_t complete_steps;

  uint32_t raw_repeat_steps;
  uint32_t repeat_steps;

  struct eri_mcontext before;
  struct eri_mcontext after;

  struct eri_mcontext repeats[];
};

static struct tst_case *current;

static struct eri_live_thread_entry *current_entry;

static uint8_t silence;

uint8_t tst_do_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
		        uint64_t a3, uint64_t a4, uint64_t a5,
		        struct eri_live_entry_syscall_info *info,
			void *entry);

static uint8_t hold_syscall;

int8_t
eri_live_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
		  uint64_t a3, uint64_t a4, uint64_t a5,
		  struct eri_live_entry_syscall_info *info,
		  void *entry)
{
  if (hold_syscall) return -1;

  silence = 1;
  tst_printf ("[%s] eri live syscall: rax = %lx, rflags = %lx\n",
	      current->name, info->rax, info->rflags);
  eri_assert (current_entry == entry);
  silence = 0;
  return tst_do_syscall (a0, a1, a2, a3, a4, a5, info, entry);
}

void
eri_live_sync_async (uint64_t cnt, void *entry)
{
  silence = 1;
  tst_printf ("[%s] eri live sync async: cnt = %lx\n",
	      current->name, cnt);
  eri_assert (current_entry == entry);
  silence = 0;
}

void
eri_live_restart_sync_async (uint64_t cnt, void *entry)
{
  silence = 1;
  tst_printf ("[%s] eri live restart sync async: cnt = %lx\n",
	      current->name, cnt);
  eri_assert (current_entry == entry);
  silence = 0;
}

uint64_t
eri_live_atomic_hash_mem (uint64_t mem, void *entry)
{
  silence = 1;
  tst_printf ("[%s] eri live atomic hash mem: mem = %lx\n",
	      current->name, mem);
  eri_assert (current_entry == entry);
  silence = 0;
  return 0;
}

void
eri_live_atomic_load (uint64_t mem, uint64_t ver, uint64_t val, void *entry)
{
  silence = 1;
  tst_printf ("[%s] eri live atomic load: mem = %lx, "
	      "ver = %lx, val = %lx\n", current->name, mem, ver, val);
  eri_assert (current_entry == entry);
  silence = 0;
}

void
eri_live_atomic_store (uint64_t mem, uint64_t ver, void *entry)
{
  silence = 1;
  tst_printf ("[%s] eri live atomic store: mem = %lx, ver = %lx\n",
	      current->name, mem, ver);
  eri_assert (current_entry == entry);
  silence = 0;
}

void
eri_live_atomic_load_store (uint64_t mem, uint64_t ver, uint64_t val,
			    void *entry)
{
  silence = 1;
  tst_printf ("[%s] eri live atomic load store: mem = %lx, "
	      "ver = %lx, val = %lx\n", current->name, mem, ver, val);
  eri_assert (current_entry == entry);
  silence = 0;
}

static void
sig_raw (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  tst_printf ("[%s:raw] sig raw: rip = %lx\n", current->name, ctx->mctx.rip);

  if (current->repeating && ctx->mctx.rip == current->raw_repeat)
    current->repeats[current->raw_repeat_steps++] = ctx->mctx;

  if (ctx->mctx.rip == current->raw_enter)
    {
      current->repeating = 1;
      current->before = ctx->mctx;
    }
  else if (ctx->mctx.rip == current->raw_leave)
    {
      current->repeating = 0;
      current->after = ctx->mctx;
    }
}

static void
sig_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (silence) return;

  if (current->step.stepping)
    {
      tst_printf ("[%s:step] sig step: step = %u, rip = %lx\n",
		  current->name, current->steps, ctx->mctx.rip);

      if (ctx->mctx.rip == current->complete && ! current->complete_steps)
	current->complete_steps = current->steps;

      if (current->repeating && ctx->mctx.rip == current->repeat)
	{
	  current->check (current, &ctx->mctx, CHECK_REPEAT);
	  current->repeats[current->repeat_steps] = ctx->mctx;
	  current->repeats[current->repeat_steps].rip = current->enter;
	  ++current->repeat_steps;
	}

      if (ctx->mctx.rip == current->repeat)
	current->repeating = 1;

      ++current->steps;
    }

  if (ctx->mctx.rip == current->enter)
    {
      current->step.stepping = 1;

      current->check (current, &ctx->mctx, CHECK_CMP_ENTER);
      current->before = ctx->mctx;
    }

  if (ctx->mctx.rip == current->leave)
    {
      current->step.stepping = 0;
      current->repeating = 0;
      current->check (current, &ctx->mctx, CHECK_CMP);
      current->after = ctx->mctx;

      eri_assert (current->raw_repeat_steps == current->repeat_steps);
    }
}

static struct eri_sigset sig_mask;
static void *sig_action;

void
eri_live_start_sig_action (int32_t sig, struct eri_stack *stack,
			   struct eri_live_entry_sig_action_info *info,
			   void *entry)
{
  eri_assert (current_entry == entry);
  stack->size = 0;
  info->rip = (uint64_t) sig_action;
  info->mask.mask_all = 0;
  info->mask.mask = sig_mask;
}

int32_t
tst_sig_step_int_check_trigger (int32_t sig, struct eri_siginfo *info,
				struct eri_ucontext *ctx)
{
  if (silence) return 0;

  tst_printf ("[%s:step_int] sig check trigger: step = %u, "
	      "trigger = %u, complete = %u, steps = %u, "
	      "rip = %lx\n",
	      current->name,
	      current->step.trigger_steps, current->step.trigger,
	      current->complete_steps, current->steps,
	      ctx->mctx.rip);

  return tst_sig_step_int_check (&current->step, ctx->mctx.rip,
				 current->enter, current->leave);
}

static void
sig_step_int_act (int32_t sig, struct eri_siginfo *info,
		  struct eri_ucontext *ctx)
{
  tst_printf ("[%s:step_int] sig trigger act\n", current->name);


  eri_assert (sig == ERI_SIGINT);
  eri_assert (++current->triggered == 1);
  current->check (current, &ctx->mctx, CHECK_STEP_INT);
  ctx->mctx.rip = current->leave;
}

static void
sigtrap_act (int32_t sig, struct eri_siginfo *info,
	     struct eri_ucontext *ctx)
{
  if ((ctx->mctx.rip == current->enter && current->repeating)
      || ctx->mctx.rip == current->leave)
    {
      tst_printf ("[%s:trap] sigtrap act: rip = %lx, "
		  "enter = %lx, leave = %lx\n",
		  current->name, ctx->mctx.rip,
		  current->enter, current->leave);

      ++current->triggered;

      eri_assert (sig == ERI_SIGTRAP);
      current->check (current, &ctx->mctx, CHECK_TRAP);

      current->repeating = ctx->mctx.rip;
   }

  if (ctx->mctx.rip == current->enter)
    current->repeating = 1;
  else if (ctx->mctx.rip == current->leave)
    current->repeating = 0;
}

static void
sigsegv_act (int32_t sig, struct eri_siginfo *info,
	     struct eri_ucontext *ctx)
{
  if (sig == ERI_SIGSEGV)
    {
      tst_printf ("[%s:segv] sigsegv act\n", current->name);

      eri_assert (! current->triggered);
      ++current->triggered;
      current->check (current, &ctx->mctx, CHECK_SEGV);
    }
}

static struct tst_context *current_ctx;

static void
tst (struct tst_rand *rand, struct tst_case *caze)
{
  eri_assert_printf ("[%s] test: data = %lx\n", caze->name, caze->data);

  struct tst_context ctx;
  uint8_t user_stack[4096];
  tst_rand_fill_tctx (rand, &ctx, user_stack + sizeof user_stack);
  ctx.rflags |= ERI_TRACE_FLAG_MASK;

  caze->init (caze, &ctx, INIT_RAW);

  current_ctx = &ctx;
  current = caze;

  /* Run raw instruction.  */
  struct eri_sigaction sa = {
    sig_raw, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
  };
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  ctx.rip = caze->raw_enter;

  tst_live_entry (&ctx);

  /* Prepare test.  */
  eri_assert_printf ("[%s] setup entry\n", caze->name);

  uint8_t entry_buf[ERI_LIVE_THREAD_ENTRY_SIZE];
  uint8_t stack[2 * 1024 * 1024];
  uint8_t sig_stack[ERI_LIVE_SIG_STACK_SIZE];
  struct eri_live_thread_entry *entry = tst_init_start_live_thread_entry (
			rand, entry_buf, stack, sizeof stack, sig_stack);

  entry->tst_skip_ctf = 1;

  current_entry = entry;

  eri_assert_printf ("[%s] setup sig stack\n", caze->name);

  ctx.rip = caze->enter;

  /* Step instruction.  */
  eri_assert_printf ("[%s:step] step instruction\n", caze->name);

  sa.act = sig_step;
  sa.flags |= ERI_SA_ONSTACK;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  caze->init (caze, &ctx, INIT_STEP);
  tst_live_entry (&ctx);

  eri_tst_live_assert_thread_entry (entry);

  /* Trigger sigint at each step.  */
  eri_assert_printf ("[%s:step_int] trigger at each step\n", caze->name);

  sa.act = tst_sig_step_int_trigger;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  sig_action = sig_step_int_act;

  for (caze->step.trigger = 0;
	caze->step.trigger <= caze->steps; ++caze->step.trigger)
    {
      eri_assert_printf ("[%s:step_int] trigger at step %u\n",
			 caze->name, caze->step.trigger);

      if (! caze->init (caze, &ctx, INIT_STEP_INT)) continue;

      tst_live_entry (&ctx);

      eri_tst_live_assert_thread_entry (entry);
      eri_assert (caze->triggered == 0 || caze->triggered == 1);
      eri_assert ((caze->step.trigger >= caze->steps) != caze->triggered);

      caze->triggered = 0;
      caze->step.trigger_steps = 0;
    }

  /* Trigger sigtrap.  */
  entry->tst_skip_ctf = 0;

  eri_assert_printf ("[%s:trap] tigger sigtrap\n", caze->name);
  sa.act = eri_live_entry_sig_action;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  sig_action = sigtrap_act;

  caze->init (caze, &ctx, INIT_TRAP);
  tst_live_entry (&ctx);

  eri_tst_live_assert_thread_entry (entry);
  eri_assert (caze->triggered);
  caze->triggered = 0;

  /* Trigger sigsegv.  */
  if (caze->init (caze, &ctx, INIT_SEGV))
    {
      eri_assert_printf ("[%s:segv] tigger sigsegv\n", caze->name);

      ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGSEGV, &sa, 0, ERI_SIG_SETSIZE);

      sig_action = sigsegv_act;

      tst_live_entry (&ctx);

      eri_tst_live_assert_thread_entry (entry);
      eri_assert (caze->triggered);
      caze->triggered = 0;

      eri_assert_printf ("[%s:segv] tigger sigsegv ctf\n", caze->name);
      caze->init (caze, &ctx, INIT_SEGV);

      ctx.rflags &= ~ERI_TRACE_FLAG_MASK;
      caze->before.rflags &= ~ERI_TRACE_FLAG_MASK;
      caze->after.rflags &= ~ERI_TRACE_FLAG_MASK;
      uint32_t i;
      for (i = 0; i < caze->repeat_steps; ++i)
	caze->repeats[i].rflags &= ~ERI_TRACE_FLAG_MASK;

      tst_live_entry (&ctx);

      ctx.rflags |= ERI_TRACE_FLAG_MASK;
      caze->before.rflags |= ERI_TRACE_FLAG_MASK;
      caze->after.rflags |= ERI_TRACE_FLAG_MASK;
      for (i = 0; i < caze->repeat_steps; ++i)
	caze->repeats[i].rflags |= ERI_TRACE_FLAG_MASK;

      sa.act = 0;
      ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGSEGV, &sa, 0, ERI_SIG_SETSIZE);

      eri_tst_live_assert_thread_entry (entry);
      eri_assert (caze->triggered);
      caze->triggered = 0;
    }

  /* Done.  */
  eri_assert_printf ("[%s] done\n", caze->name);

  sa.act = 0;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  struct eri_stack st = { 0, ERI_SS_DISABLE };
  ERI_ASSERT_SYSCALL (sigaltstack, &st, 0);

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_GS, 0);
}

#define COMMON_CHECK_CMP(caze, mctx) \
  do {									\
    tst_assert_mctx_eq (&(caze)->after, mctx, TST_MEQ_NRIP);		\
    eri_assert ((mctx)->rip == (caze)->leave);				\
  } while (0)

#define NON_REP_CHECK_STEP_INT(caze, mctx) \
  tst_assert_mctx_eq (							\
		(caze)->step.trigger_steps < (caze)->complete_steps	\
		  ? &(caze)->before : &(caze)->after, mctx, 0)
#define NON_REP_CHECK_TRAP(caze, mctx) \
  tst_assert_mctx_eq (&(caze)->after, mctx, 0)
#define NON_REP_CHECK(caze, mctx, type) \
  do {									\
    if ((type) == CHECK_STEP_INT)					\
      NON_REP_CHECK_STEP_INT (caze, mctx);				\
    else if ((type) == CHECK_TRAP)					\
      NON_REP_CHECK_TRAP (caze, mctx);					\
  } while (0)

static uint8_t
do_syscall_init (struct tst_case *caze, struct tst_context *ctx,
		 uint8_t type)
{
  ctx->rax = __NR_gettid;
  return type != INIT_SEGV;
}

static void
do_syscall_check (struct tst_case *caze,
		  struct eri_mcontext *mctx, uint8_t type)
{
  if (type == CHECK_CMP)
    {
      tst_assert_mctx_eq (&caze->after, mctx,
			  TST_MEQ_NRCX | TST_MEQ_NRIP);
      eri_assert (mctx->rcx == caze->leave);
      eri_assert (mctx->rip == caze->leave);
    }
  else NON_REP_CHECK (caze, mctx, type);
}

static uint8_t
hold_syscall_init (struct tst_case *caze, struct tst_context *ctx,
		   uint8_t type)
{
  if (type != INIT_RAW && type != INIT_STEP)
    caze->before.rip = caze->after.rip = caze->enter;
  return ! (type == INIT_STEP_INT && caze->step.trigger == caze->steps)
	 && type != INIT_SEGV;
}

static void
hold_syscall_check (struct tst_case *caze,
		    struct eri_mcontext *mctx, uint8_t type)
{
  if (type == CHECK_CMP_ENTER)
    {
      if (caze->steps) mctx->rip = caze->leave;
    }
  else if (type == CHECK_CMP)
    COMMON_CHECK_CMP (caze, mctx);
  else if (type == CHECK_STEP_INT)
    NON_REP_CHECK_STEP_INT (caze, mctx);
  else if (type == CHECK_TRAP)
    {
      NON_REP_CHECK_TRAP (caze, mctx);
      mctx->rip = caze->leave;
    }
}

#define SYNC_JMP_REG	TST_LIVE_SYNC_JMP_REG
#define SYNC_JMP_UREG	TST_LIVE_SYNC_JMP_UREG

static uint8_t
sync_jmp_init (struct tst_case *caze, struct tst_context *ctx,
	       uint8_t type)
{
  if (type == INIT_RAW)
    ctx->SYNC_JMP_REG = (uint64_t) (&caze->raw_leave);
  else if (type == INIT_SEGV) ctx->SYNC_JMP_REG = 0;
  else ctx->SYNC_JMP_REG = (uint64_t) (&caze->leave);
  return 1;
}

static void
sync_jmp_check (struct tst_case *caze, struct eri_mcontext *mctx,
		uint8_t type)
{
  if (type == CHECK_CMP)
    {
      tst_assert_mctx_eq (&caze->after, mctx,
		_ERS_PASTE (TST_MEQ_N, SYNC_JMP_UREG) | TST_MEQ_NRIP);
      eri_assert (mctx->SYNC_JMP_REG == (uint64_t) &caze->leave);
      eri_assert (mctx->rip == caze->leave);
    }
  else if (type == CHECK_SEGV)
    {
      eri_assert (mctx->SYNC_JMP_REG == 0);
      mctx->SYNC_JMP_REG = (uint64_t) &caze->leave;
      tst_assert_mctx_eq (&caze->before, mctx, 0);
    }
  else NON_REP_CHECK (caze, mctx, type);
}

#define SYNC_REP_HALF_SIZE	2
#define SYNC_REP_SIZE		(2 * SYNC_REP_HALF_SIZE)

struct tst_sync_rep
{
  struct tst_rand *rand;
  uint8_t src[SYNC_REP_SIZE * 8];
  uint8_t *dst;
};

static uint8_t
sync_rep_init (struct tst_case *caze, struct tst_context *ctx,
	       uint8_t type)
{
  struct tst_sync_rep *rep = caze->data;
  ctx->rcx = SYNC_REP_SIZE;
  ctx->rsi = (uint64_t) rep->src;
  ctx->rdi = (uint64_t) rep->dst;

  tst_rand_fill (rep->rand, rep->src, sizeof rep->src);
  if (type == INIT_TRAP)
    caze->repeat_steps = 0;
  else if (type == INIT_SEGV)
    ERI_ASSERT_SYSCALL (mprotect,
			eri_round_up ((uint64_t) rep->dst, 4096), 4096, 0);
  return 1;
}

static void
sync_rep_check (struct tst_case *caze, struct eri_mcontext *mctx,
		uint8_t type)
{
  if (type == CHECK_CMP)
    COMMON_CHECK_CMP (caze, mctx);
  else if (type == CHECK_REPEAT)
    {
      eri_assert (caze->repeat_steps < caze->raw_repeat_steps);
      tst_assert_mctx_eq (caze->repeats + caze->repeat_steps, mctx,
			  TST_MEQ_NRIP);
    }
  else if (type == CHECK_STEP_INT)
    {
      if (caze->step.trigger_steps <= caze->complete_steps)
	tst_assert_mctx_eq (&caze->before, mctx, 0);
      else
	{
	  uint32_t steps
		= caze->step.trigger_steps - caze->complete_steps - 1;
	  if (steps < caze->repeat_steps)
	    tst_assert_mctx_eq (caze->repeats + steps, mctx, 0);
	  else
	    tst_assert_mctx_eq (&caze->after, mctx, 0);
	}
    }
  else if (type == CHECK_TRAP)
    {
      if (caze->repeat_steps < caze->raw_repeat_steps)
	tst_assert_mctx_eq (caze->repeats + caze->repeat_steps++, mctx, 0);
      else
	tst_assert_mctx_eq (&caze->after, mctx, 0);
    }
  else if (type == CHECK_SEGV)
    {
      tst_assert_mctx_eq (caze->repeats + SYNC_REP_HALF_SIZE - 1, mctx, 0);
      struct tst_sync_rep *rep = caze->data;
      ERI_ASSERT_SYSCALL (mprotect,
			  eri_round_up ((uint64_t) rep->dst, 4096), 4096,
			  ERI_PROT_READ | ERI_PROT_WRITE);
    }
}

#define AT_INIT_MEM(reg) \
  ctx->reg = type != INIT_SEGV ? (uint64_t) caze->data : 0

#define AT_INIT(name, val, reg, ...) \
static uint8_t								\
_ERS_PASTE (name, _init) (struct tst_case *caze,			\
			  struct tst_context *ctx, uint8_t type)	\
{									\
  *(uint64_t *) caze->data = val;					\
  __VA_ARGS__								\
  AT_INIT_MEM (reg);							\
  return 1;								\
}									\

#define AT_CHECK_SEGV(reg) \
  do {									\
    eri_assert (mctx->reg == 0);					\
    mctx->reg = (uint64_t) caze->data;					\
    tst_assert_mctx_eq (&caze->before, mctx, 0);			\
  } while (0)

#define AT_CHECK_LOAD(name, val, reg) \
static void								\
_ERS_PASTE (name, _check) (struct tst_case *caze,			\
			   struct eri_mcontext *mctx, uint8_t type)	\
{									\
  eri_assert (*(uint64_t *) caze->data == (val));			\
  if (type == CHECK_CMP)						\
    COMMON_CHECK_CMP (caze, mctx);					\
  else if (type == CHECK_SEGV)						\
    AT_CHECK_SEGV (reg);						\
  else NON_REP_CHECK (caze, mctx, type);				\
}

#define LOAD_VAL(sz)		TST_LIVE_VAL (sz, 0xef)
#define LOAD_REG_DST		TST_LIVE_LOAD_REG_DST (q)
#define LOAD_REG_MEM		TST_LIVE_LOAD_REG_MEM

#define LOAD_CALLBACKS(sz) \
AT_INIT (_ERS_PASTE (load, sz), LOAD_VAL (sz), LOAD_REG_MEM,		\
	 ctx->LOAD_REG_DST = 0;)					\
AT_CHECK_LOAD (_ERS_PASTE (load, sz), LOAD_VAL (sz), LOAD_REG_MEM)

TST_ATOMIC_SIZES (LOAD_CALLBACKS)

#define CMP_REG			TST_LIVE_CMP_REG
#define CMP_REG_MEM		TST_LIVE_CMP_REG_MEM

#define CMP_CALLBACKS(sz, name, eq) \
AT_INIT (_ERS_PASTE (name, sz), ctx->rsp - 16 - ! (eq), CMP_REG_MEM)	\
AT_CHECK_LOAD (_ERS_PASTE (name, sz), mctx->rsp - ! (eq), CMP_REG_MEM)

TST_ATOMIC_SIZES (CMP_CALLBACKS, cmp_eq, 1)
TST_ATOMIC_SIZES (CMP_CALLBACKS, cmp_ne, 0)

#define AT_CHECK_STORE(name, old_val, new_val, reg) \
static void								\
_ERS_PASTE (name, _check) (struct tst_case *caze,			\
			   struct eri_mcontext *mctx, uint8_t type)	\
{									\
  if (type == CHECK_CMP)						\
    {									\
      COMMON_CHECK_CMP (caze, mctx);					\
      eri_assert (*(uint64_t *) caze->data == (new_val));		\
    }									\
  else if (type == CHECK_STEP_INT)					\
    {									\
      NON_REP_CHECK_STEP_INT (caze, mctx);				\
      eri_assert (*(uint64_t *) caze->data				\
		    == (caze->step.trigger_steps < caze->complete_steps	\
			  ? (old_val) : (new_val)));			\
    }									\
  else if (type == CHECK_TRAP)						\
    {									\
      NON_REP_CHECK_TRAP (caze, mctx);					\
      eri_assert (*(uint64_t *) caze->data == (new_val));		\
    }									\
  else if (type == CHECK_SEGV)						\
    {									\
      AT_CHECK_SEGV (reg);						\
      eri_assert (*(uint64_t *) caze->data == (old_val));		\
    }									\
}

#define STORE_IMM_VAL		TST_LIVE_STORE_IMM_VAL
#define STORE_REG_SRC		TST_LIVE_STORE_REG_SRC (q)
#define STORE_REG_MEM		TST_LIVE_STORE_REG_MEM

#define STORE_CALLBACKS(sz, name, reg) \
AT_INIT (_ERS_PASTE (name, sz), 0, STORE_REG_MEM,			\
	 ERI_PP_IF (reg, ctx->STORE_REG_SRC = STORE_IMM_VAL (sz);))	\
AT_CHECK_STORE (_ERS_PASTE (name, sz),					\
	       0, STORE_IMM_VAL (sz), STORE_REG_MEM)

TST_ATOMIC_SIZES32 (STORE_CALLBACKS, store_imm, 0)
TST_ATOMIC_SIZES (STORE_CALLBACKS, store_reg, 1)

#define INC_DEC_VAL(sz)		TST_LIVE_VAL (sz, 0x01)
#define INC_REG_MEM		TST_LIVE_INC_REG_MEM
#define DEC_REG_MEM		TST_LIVE_DEC_REG_MEM

#define INC_DEC_CALLBACKS(sz, uinc, inc, op) \
AT_INIT (_ERS_PASTE (inc, sz), INC_DEC_VAL (sz),			\
	 _ERS_PASTE (uinc, _REG_MEM))					\
AT_CHECK_STORE (_ERS_PASTE (inc, sz), INC_DEC_VAL (sz),			\
		INC_DEC_VAL (sz) op 1, _ERS_PASTE (uinc, _REG_MEM))

TST_ATOMIC_SIZES (INC_DEC_CALLBACKS, INC, inc, +)
TST_ATOMIC_SIZES (INC_DEC_CALLBACKS, DEC, dec, -)

#define XCHG_VAL(sz)		TST_LIVE_VAL (sz, 0xab)
#define XCHG_VAL_MEM(sz)	TST_LIVE_VAL (sz, 0xcd)
#define XCHG_REG		TST_LIVE_XCHG_REG (q)
#define XCHG_REG_MEM		TST_LIVE_XCHG_REG_MEM

#define XCHG_CALLBACKS(sz) \
AT_INIT (_ERS_PASTE (xchg, sz), XCHG_VAL_MEM (sz), XCHG_REG_MEM,	\
	 ctx->XCHG_REG = XCHG_VAL (sz);)				\
AT_CHECK_STORE (_ERS_PASTE (xchg, sz), XCHG_VAL_MEM (sz),		\
		XCHG_VAL (sz), XCHG_REG_MEM)

TST_ATOMIC_SIZES (XCHG_CALLBACKS)

#define _TST_TYPE_b		uint8_t
#define _TST_TYPE_w		uint16_t
#define _TST_TYPE_l		uint32_t
#define _TST_TYPE_q		uint64_t
#define TST_TYPE(sz)		_ERS_PASTE (_TST_TYPE_, sz)

#define CMPXCHG_VAL(sz)		TST_LIVE_VAL (sz, 0x01)
#define CMPXCHG_REG		TST_LIVE_CMPXCHG_REG (q)

#define CMPXCHG_CALLBACKS(sz, name, eq) \
AT_INIT (_ERS_PASTE (name, sz), CMPXCHG_VAL (sz), CMPXCHG_REG,		\
	 ctx->rax = CMPXCHG_VAL (sz) + ! (eq);)				\
AT_CHECK_STORE (_ERS_PASTE (name, sz), CMPXCHG_VAL (sz),		\
	        (eq) ? (TST_TYPE (sz)) (uint64_t) caze->data		\
		     : CMPXCHG_VAL (sz),				\
		CMPXCHG_REG)

TST_ATOMIC_SIZES (CMPXCHG_CALLBACKS, cmpxchg_eq, 1)
TST_ATOMIC_SIZES (CMPXCHG_CALLBACKS, cmpxchg_ne, 0)

uint64_t
tst_main (void)
{
  struct tst_rand rand;
  tst_rand_seed (&rand, ERI_ASSERT_SYSCALL_RES (getpid));

  eri_sigaddset (&sig_mask, ERI_SIGSEGV);

  static uint64_t atomic_mem_table;
  eri_live_entry_atomic_mem_table = &atomic_mem_table;

#define ENTRY_ADDR_FIELDS(caze) \
  (uint64_t) _ERS_PASTE (tst_live_entry_raw_enter_, caze),		\
  (uint64_t) _ERS_PASTE (tst_live_entry_raw_leave_, caze),		\
  (uint64_t) _ERS_PASTE (tst_live_entry_enter_, caze),			\
  (uint64_t) _ERS_PASTE (tst_live_entry_leave_, caze)

#define ENTRY_FIELDS(caze) \
  #caze,								\
  _ERS_PASTE (caze, _init), _ERS_PASTE (caze, _check),			\
  ENTRY_ADDR_FIELDS (caze)

  struct tst_case do_syscall = {
    ENTRY_FIELDS (do_syscall),
    (uint64_t) ERI_TST_LIVE_COMPLETE_START_SYMBOL (do_syscall)
  };

  tst (&rand, &do_syscall);

  hold_syscall = 1;
  struct tst_case hold_syscall = {
    ENTRY_FIELDS (hold_syscall),
    (uint64_t) ERI_TST_LIVE_COMPLETE_START_SYMBOL (hold_syscall)
  };

  tst (&rand, &hold_syscall);

  struct tst_case sync_jmp = {
    ENTRY_FIELDS (sync_jmp),
    (uint64_t) tst_live_entry_leave_sync_jmp
  };

  tst (&rand, &sync_jmp);

  struct tst_sync_rep rep = { &rand };
  uint8_t *sync_dst = (uint8_t *) ERI_ASSERT_SYSCALL_RES (
	    mmap, 0, 4096 * 2, ERI_PROT_READ | ERI_PROT_WRITE,
	    ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  rep.dst = sync_dst + 4096 - SYNC_REP_HALF_SIZE * 8;

  uint8_t sync_rep[sizeof (struct tst_case)
		     + sizeof (struct eri_mcontext) * SYNC_REP_SIZE - 1];
  struct tst_case sync_rep_fields = {
    ENTRY_FIELDS (sync_rep),
    (uint64_t) tst_live_sync_rep,
    &rep,
    (uint64_t) tst_live_raw_sync_rep,
    (uint64_t) tst_live_sync_rep
  };
#define sync_rep	(*(struct tst_case *) sync_rep)
  sync_rep = sync_rep_fields;

  tst (&rand, &sync_rep);
  eri_assert (eri_memcmp (rep.src, rep.dst, SYNC_REP_SIZE * 8) == 0);

  ERI_ASSERT_SYSCALL (munmap,
		      eri_round_down ((uint64_t) rep.dst, 4096), 4096 * 2);

#define AT_TST(sz, name, at) \
  uint64_t _ERS_PASTE2 (name, sz, _val);				\
  struct tst_case _ERS_PASTE (name, sz) = {				\
    #name #sz,								\
    _ERS_PASTE2 (name, sz, _init), _ERS_PASTE2 (name, sz, _check),	\
    ENTRY_ADDR_FIELDS (_ERS_PASTE (name, sz)),				\
    (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_SYMBOL (sz, at),	\
    &_ERS_PASTE2 (name, sz, _val)					\
  };									\
									\
  tst (&rand, &_ERS_PASTE (name, sz));

  TST_ATOMIC_SIZES (AT_TST, load, load);

  TST_ATOMIC_SIZES (AT_TST, cmp_eq, load);
  TST_ATOMIC_SIZES (AT_TST, cmp_ne, load);

  TST_ATOMIC_SIZES32 (AT_TST, store_imm, store);
  TST_ATOMIC_SIZES (AT_TST, store_reg, store);

  TST_ATOMIC_SIZES (AT_TST, inc, inc);
  TST_ATOMIC_SIZES (AT_TST, dec, dec);

  TST_ATOMIC_SIZES (AT_TST, xchg, xchg);

  TST_ATOMIC_SIZES (AT_TST, cmpxchg_eq, cmpxchg);
  TST_ATOMIC_SIZES (AT_TST, cmpxchg_ne, cmpxchg);

  return 0;
}
