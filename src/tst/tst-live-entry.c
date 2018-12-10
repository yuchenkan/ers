#include "tst/tst-live-entry.h"

#include "live.h"

#include "lib/syscall.h"
#include "lib/printf.h"
#include "public/comm.h"

struct rand
{
  uint64_t val;
};

static uint64_t
rand_next (struct rand *rand)
{
  rand->val ^= rand->val << 13;
  rand->val ^= rand->val >> 7;
  rand->val ^= rand->val << 17;
  return rand->val;
}

static void
rand_seed (struct rand *rand, uint64_t seed)
{
  rand->val = seed * seed * seed * seed;
  rand_next (rand);
}

static void
rand_fill (struct rand *rand, void *buf, uint64_t size)
{
  uint64_t i;
  for (i = 0; i < size / sizeof i; ++i)
    *(uint64_t *) ((uint8_t *) buf + i * sizeof i) = rand_next (rand);
  if (size % sizeof i)
    {
      uint64_t v = rand_next (rand);
      eri_memcpy ((uint8_t *) buf + i * 8, &v, size % sizeof i);
    }
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

#define INIT_RAW	0
#define INIT_TST	1
#define INIT_SIGSEGV	2

#define CHECK_CMP	0
#define CHECK_BEFORE	1
#define CHECK_AFTER	2
#define CHECK_SIGSEGV	3

struct tst_entry
{
  char *name;

  uint8_t (*init) (struct tst_entry *, struct tst_context *, uint8_t type);
  void (*check) (struct tst_entry *, struct eri_mcontext *, uint8_t type);

  uint64_t raw_enter;
  uint64_t raw_leave;

  uint64_t enter;
  uint64_t leave;

  uint64_t complete;

  void *data;

  uint8_t stepping	: 1;
  uint8_t triggered	: 1;

  uint32_t steps;
  uint32_t complete_steps;

  uint32_t trigger;
  uint32_t trigger_steps;

  struct eri_mcontext before;
  struct eri_mcontext after;
};

static struct tst_entry *current;

static void
sig_raw (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  eri_assert_printf ("[%s] sig raw: rip = %lx\n",
		     current->name, ctx->mctx.rip);

  if (ctx->mctx.rip == current->raw_enter)
    current->before = ctx->mctx;
  else if (ctx->mctx.rip == current->raw_leave)
    current->after = ctx->mctx;
}

static void
sig_step (int32_t sig, struct eri_siginfo *info, struct eri_ucontext *ctx)
{
  if (current->stepping)
    {
      eri_assert_printf ("[%s] sig step: step = %u, rip = %lx\n",
			 current->name, current->steps, ctx->mctx.rip);

      if (ctx->mctx.rip == current->complete)
	current->complete_steps = current->steps;

      ++current->steps;
    }

  if (ctx->mctx.rip == current->enter)
    {
      current->stepping = 1;
      current->before = ctx->mctx;
    }

  if (ctx->mctx.rip == current->leave)
    {
      current->stepping = 0;
      current->check (current, &ctx->mctx, CHECK_CMP);
      current->after = ctx->mctx;
    }
}

void *sig_act;

int32_t
sig_check_trigger (int32_t sig, struct eri_siginfo *info,
		   struct eri_ucontext *ctx)
{
  if (current->triggered) return 0;

  if (current->stepping)
    {
      eri_assert_printf ("[%s] sig check trigger: step = %u, "
			 "trigger = %u, complete = %u, steps = %u, "
			 "rip = %lx\n",
			 current->name,
			 current->trigger_steps, current->trigger,
			 current->complete_steps, current->steps,
			 ctx->mctx.rip);

      if (current->trigger_steps == current->trigger)
	{
	  current->triggered = 1;
	  current->stepping = 0;
	  return ERI_SIGINT;
	}

      ++current->trigger_steps;
    }

  if (ctx->mctx.rip == current->enter)
    current->stepping = 1;
  if (ctx->mctx.rip == current->leave)
    current->stepping = 0;

  return 0;
}

void sig_trigger (int32_t sig, struct eri_siginfo *info,
		  struct eri_ucontext *ctx);

static void
sig_trigger_act (int32_t sig, struct eri_siginfo *info,
		 struct eri_ucontext *ctx)
{
  eri_assert_printf ("[%s] sig trigger act\n", current->name);

  eri_assert (sig == ERI_SIGINT);
  uint8_t before = current->trigger_steps < current->complete_steps;
  assert_eq (before ? &current->before : &current->after, &ctx->mctx, 0);
  current->check (current, &ctx->mctx, before ? CHECK_BEFORE : CHECK_AFTER);
}

static void
sigtrap_act (int32_t sig, struct eri_siginfo *info,
	     struct eri_ucontext *ctx)
{
  if (ctx->mctx.rip == current->leave)
    {
      eri_assert_printf ("[%s] sigtrag act\n", current->name);

      eri_assert (! current->triggered);
      current->triggered = 1;

      eri_assert (sig == ERI_SIGTRAP);
      assert_eq (&current->after, &ctx->mctx, 0);
      current->check (current, &ctx->mctx, CHECK_AFTER);
   }
}

static void
sigsegv_act (int32_t sig, struct eri_siginfo *info,
	     struct eri_ucontext *ctx)
{
  if (sig == ERI_SIGSEGV)
    {
      eri_assert_printf ("[%s] sigsegv act\n", current->name);

      eri_assert (! current->triggered);
      current->triggered = 1;
      current->check (current, &ctx->mctx, CHECK_SIGSEGV);
    }
}

static void
assert_thread (struct eri_live_thread *thread)
{
  eri_assert (thread->common.mark == 0);
  eri_assert (thread->common.dir == 0);
  eri_assert (thread->rsp == thread->top);
  eri_assert (thread->fix_restart == 0);
  eri_assert (thread->restart == 0);
}

static struct tst_context *current_ctx;

static void
tst (struct rand *rand, struct tst_entry *entry)
{
  struct tst_context ctx;
  rand_fill (rand, &ctx, sizeof ctx);

  uint8_t ustk[4096];
  ctx.rsp = (uint64_t) ustk + sizeof ustk;
  ctx.rflags &= 0xd5;
  ctx.rflags |= ERI_TRACE_FLAG_MASK;

  entry->init (entry, &ctx, INIT_RAW);

  current_ctx = &ctx;
  current = entry;

  /* Run raw instruction.  */
  struct eri_sigaction sa = {
    sig_raw, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn
  };
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  ctx.rip = entry->raw_enter;

  tst_live_entry (&ctx);

  /* Prepare test.  */
  eri_assert_printf ("[%s] setup thread\n", entry->name);

  uint8_t thread_buf[eri_size_of (struct eri_live_thread, 16)
		       + (eri_live_thread_text_end - eri_live_thread_text)];
  rand_fill (rand, thread_buf, sizeof thread_buf);

  struct eri_live_thread *thread = (struct eri_live_thread *) thread_buf;
  uint8_t stk[2 * 1024 * 1024];
  rand_fill (rand, stk, sizeof stk);

  eri_live_init_thread (thread, 0, (uint64_t) stk + sizeof stk, sizeof stk);
  thread->tst_skip_ctf = 1;

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_GS, thread);

  eri_assert_printf ("[%s] setup sig stack\n", entry->name);

  uint8_t sstk[ERI_SIG_STACK_SIZE];
  rand_fill (rand, sstk, sizeof sstk);
  *(struct eri_live_thread **) sstk = thread;
  struct eri_stack st = { sstk, 0, sizeof sstk };
  ERI_ASSERT_SYSCALL (sigaltstack, &st, 0);

  ctx.rip = entry->enter;

  /* Step instruction.  */
  eri_assert_printf ("[%s] step instruction\n", entry->name);

  sa.act = sig_step;
  sa.flags |= ERI_SA_ONSTACK;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  entry->init (entry, &ctx, INIT_TST);
  tst_live_entry (&ctx);

  assert_thread (thread);

  /* Trigger sigint at each step.  */
  eri_assert_printf ("[%s] trigger at each step\n", entry->name);

  sa.act = sig_trigger;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  sig_act = sig_trigger_act;

  for (entry->trigger = 0; entry->trigger <= entry->steps; ++entry->trigger)
    {
      eri_assert_printf ("[%s] trigger at step %u\n",
			 entry->name, entry->trigger);

      entry->init (entry, &ctx, INIT_TST);
      tst_live_entry (&ctx);

      assert_thread (thread);
      if (entry->trigger < entry->steps) eri_assert (entry->triggered);
      else eri_assert (! entry->triggered);

      entry->triggered = 0;
      entry->trigger_steps = 0;
    }

  /* Trigger sigtrap.  */
  thread->tst_skip_ctf = 0;

  eri_assert_printf ("[%s] tigger sigtrap\n", entry->name);
  sa.act = eri_live_sigaction;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  sig_act = sigtrap_act;

  entry->init (entry, &ctx, INIT_TST);
  tst_live_entry (&ctx);

  assert_thread (thread);
  eri_assert (entry->triggered);
  entry->triggered = 0;

  /* Trigger sigsegv.  */
  if (entry->init (entry, &ctx, INIT_SIGSEGV))
    {
      ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGSEGV, &sa, 0, ERI_SIG_SETSIZE);

      sig_act = sigsegv_act;

      tst_live_entry (&ctx);

      sa.act = 0;
      ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGSEGV, &sa, 0, ERI_SIG_SETSIZE);

      assert_thread (thread);
      eri_assert (entry->triggered);
      entry->triggered = 0;
    }

  /* Done.  */
  eri_assert_printf ("[%s] done\n", entry->name);

  sa.act = 0;
  ERI_ASSERT_SYSCALL (rt_sigaction, ERI_SIGTRAP, &sa, 0, ERI_SIG_SETSIZE);

  st.flags = ERI_SS_DISABLE;
  ERI_ASSERT_SYSCALL (sigaltstack, &st, 0);

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_GS, 0);
}

static uint8_t
syscall_init (struct tst_entry *entry, struct tst_context *ctx, uint8_t type)
{
  ctx->rax = __NR_gettid;
  return type != INIT_SIGSEGV;
}

static void
syscall_check (struct tst_entry *entry,
	       struct eri_mcontext *mctx, uint8_t type)
{
  if (type == CHECK_CMP)
    {
      assert_eq (&entry->after, mctx, EQ_NRCX | EQ_NRIP);
      eri_assert (mctx->rcx == entry->enter);
    }
}

#define SYNC_ASYNC_REG		TST_LIVE_SYNC_ASYNC_REG
#define SYNC_ASYNC_UREG		TST_LIVE_SYNC_ASYNC_UREG

static uint8_t
sync_async_init (struct tst_entry *entry, struct tst_context *ctx,
		 uint8_t type)
{
  if (type == INIT_RAW)
    ctx->SYNC_ASYNC_REG = (uint64_t) (&entry->raw_leave);
  else if (type == INIT_TST)
    ctx->SYNC_ASYNC_REG = (uint64_t) (&entry->leave);
  else if (type == INIT_SIGSEGV)
    ctx->SYNC_ASYNC_REG = 0;
  return 1;
}

static void
sync_async_check (struct tst_entry *entry, struct eri_mcontext *mctx,
		  uint8_t type)
{
  if (type == CHECK_CMP)
    {
      assert_eq (&entry->after, mctx,
		 _ERS_PASTE (EQ_N, SYNC_ASYNC_UREG) | EQ_NRIP);
      eri_assert (mctx->SYNC_ASYNC_REG == (uint64_t) &entry->leave);
    }
  else if (type == CHECK_SIGSEGV)
    {
      eri_assert (mctx->SYNC_ASYNC_REG == 0);
      mctx->SYNC_ASYNC_REG = (uint64_t) &entry->leave;
      assert_eq (&entry->before, mctx, 0);
    }
}

#define AT_NAME			_ERS_PASTE2

#define AT_INIT_MEM(reg) \
  ctx->reg = type != INIT_SIGSEGV ? (uint64_t) entry->data : 0

#define AT_INIT(name, val, reg, ...) \
static uint8_t								\
_ERS_PASTE (name, _init) (struct tst_entry *entry,			\
			  struct tst_context *ctx, uint8_t type)	\
{									\
  *(uint64_t *) entry->data = val;					\
  __VA_ARGS__								\
  AT_INIT_MEM (reg);							\
  return 1;								\
}									\

#define AT_CHECK_SIGSEGV(reg) \
  do {									\
    eri_assert (mctx->reg == 0);					\
    mctx->reg = (uint64_t) entry->data;					\
    assert_eq (&entry->before, mctx, 0);				\
  } while (0)

#define AT_CHECK_LOAD(name, val, reg) \
static void								\
_ERS_PASTE (name, _check) (struct tst_entry *entry,			\
			   struct eri_mcontext *mctx, uint8_t type)	\
{									\
  eri_assert (*(uint64_t *) entry->data == (val));			\
  if (type == CHECK_CMP)						\
    assert_eq (&entry->after, mctx, EQ_NRIP);				\
  else if (type == CHECK_SIGSEGV)					\
    AT_CHECK_SIGSEGV (reg);						\
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

#define AT_CHECK_STOR(name, old_val, new_val, reg) \
static void								\
_ERS_PASTE (name, _check) (struct tst_entry *entry,			\
			   struct eri_mcontext *mctx, uint8_t type)	\
{									\
  if (type == CHECK_CMP)						\
    {									\
      assert_eq (&entry->after, mctx, EQ_NRIP);				\
      eri_assert (*(uint64_t *) entry->data == (new_val));		\
    }									\
  else if (type == CHECK_BEFORE)					\
    eri_assert (*(uint64_t *) entry->data == (old_val));		\
  else if (type == CHECK_AFTER)						\
    eri_assert (*(uint64_t *) entry->data == (new_val));		\
  else if (type == CHECK_SIGSEGV)					\
    {									\
      AT_CHECK_SIGSEGV (reg);						\
      eri_assert (*(uint64_t *) entry->data == (old_val));		\
    }									\
}

#define STOR_IMM_VAL		TST_LIVE_STOR_IMM_VAL
#define STOR_REG_SRC		TST_LIVE_STOR_REG_SRC (q)
#define STOR_REG_MEM		TST_LIVE_STOR_REG_MEM

#define STOR_CALLBACKS(sz, name, reg) \
AT_INIT (_ERS_PASTE (name, sz), 0, STOR_REG_MEM,			\
	 ERI_PP_IF (reg, ctx->STOR_REG_SRC = STOR_IMM_VAL (sz);))	\
AT_CHECK_STOR (_ERS_PASTE (name, sz),					\
	       0, STOR_IMM_VAL (sz), STOR_REG_MEM)

TST_ATOMIC_SIZES32 (STOR_CALLBACKS, stor_imm, 0)
TST_ATOMIC_SIZES (STOR_CALLBACKS, stor_reg, 1)

#define INC_DEC_VAL(sz)		TST_LIVE_VAL (sz, 0x01)
#define INC_REG_MEM		TST_LIVE_INC_REG_MEM
#define DEC_REG_MEM		TST_LIVE_DEC_REG_MEM

#define INC_DEC_CALLBACKS(sz, uinc, inc, op) \
AT_INIT (_ERS_PASTE (inc, sz), INC_DEC_VAL (sz),			\
	 _ERS_PASTE (uinc, _REG_MEM))					\
AT_CHECK_STOR (_ERS_PASTE (inc, sz), INC_DEC_VAL (sz),			\
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
AT_CHECK_STOR (_ERS_PASTE (xchg, sz), XCHG_VAL_MEM (sz), XCHG_VAL (sz),	\
	       XCHG_REG_MEM)

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
AT_CHECK_STOR (_ERS_PASTE (name, sz), CMPXCHG_VAL (sz),			\
	       (eq) ? (TST_TYPE (sz)) (uint64_t) entry->data		\
		    : CMPXCHG_VAL (sz),					\
	       CMPXCHG_REG)

TST_ATOMIC_SIZES (CMPXCHG_CALLBACKS, cmpxchg_eq, 1)
TST_ATOMIC_SIZES (CMPXCHG_CALLBACKS, cmpxchg_ne, 0)

uint64_t
tst_main (void)
{
  struct rand rand;
  rand_seed (&rand, ERI_ASSERT_SYSCALL_RES (getpid));

  extern struct eri_sigset eri_live_sigempty; /* TODO */
  eri_sigaddset (&eri_live_sigempty, ERI_SIGSEGV);

  extern struct eri_live_internal eri_live_internal;
  static uint64_t atomic_mem_table;
  eri_live_internal.atomic_mem_table = &atomic_mem_table;

#define ENTRY_ADDR_FIELDS(entry) \
  (uint64_t) _ERS_PASTE (tst_live_entry_raw_enter_, entry),		\
  (uint64_t) _ERS_PASTE (tst_live_entry_raw_leave_, entry),		\
  (uint64_t) _ERS_PASTE (tst_live_entry_enter_, entry),			\
  (uint64_t) _ERS_PASTE (tst_live_entry_leave_, entry)

#define ENTRY_FIELDS(entry) \
  #entry,								\
  _ERS_PASTE (entry, _init), _ERS_PASTE (entry, _check),		\
  ENTRY_ADDR_FIELDS (entry)

  struct tst_entry syscall = {
    ENTRY_FIELDS (syscall),
    (uint64_t) ERI_TST_LIVE_COMPLETE_START_NAME (syscall)
  };

  tst (&rand, &syscall);

  struct tst_entry sync_async = {
    ENTRY_FIELDS (sync_async),
    (uint64_t) tst_live_entry_leave_sync_async
  };

  tst (&rand, &sync_async);

#define AT_TST(sz, name, at) \
  uint64_t AT_NAME (name, sz, _val);					\
  struct tst_entry _ERS_PASTE (name, sz) = {				\
    #name #sz,								\
    AT_NAME (name, sz, _init), AT_NAME (name, sz, _check),		\
    ENTRY_ADDR_FIELDS (_ERS_PASTE (name, sz)),				\
    (uint64_t) ERI_TST_LIVE_ATOMIC_COMPLETE_START_NAME (sz, at),	\
    &AT_NAME (name, sz, _val)						\
  };									\
									\
  tst (&rand, &_ERS_PASTE (name, sz));

  TST_ATOMIC_SIZES (AT_TST, load, load);

  TST_ATOMIC_SIZES (AT_TST, cmp_eq, load);
  TST_ATOMIC_SIZES (AT_TST, cmp_ne, load);

  TST_ATOMIC_SIZES32 (AT_TST, stor_imm, stor);
  TST_ATOMIC_SIZES (AT_TST, stor_reg, stor);

  TST_ATOMIC_SIZES (AT_TST, inc, inc);
  TST_ATOMIC_SIZES (AT_TST, dec, dec);

  TST_ATOMIC_SIZES (AT_TST, xchg, xchg);

  TST_ATOMIC_SIZES (AT_TST, cmpxchg_eq, cmpxchg);
  TST_ATOMIC_SIZES (AT_TST, cmpxchg_ne, cmpxchg);

  return 0;
}
