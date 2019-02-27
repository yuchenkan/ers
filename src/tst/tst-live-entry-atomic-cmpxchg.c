#include <compiler.h>
#include <common.h>

#include <public/impl.h>
#include <lib/util.h>
#include <lib/registers.h>
#include <tst/tst-syscall.h>
#include <tst/tst-live-entry-atomic.h>
#include <tst/generated/registers.h>

#define OP(reg, mem, sz) \
  ERI_PASTE (ERI_PASTE2 (cmpxchg_, reg, _), ERI_PASTE2 (mem, _, sz))

#define ASM_SIZE(sz, creg, reg, mem) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (reg, mem, sz),				\
	ERI_EVAL (ERI_PASTE (cmpxchg, sz)				\
			%ERI_PASTE (ERI_, creg) (sz), (%mem)),		\
	_ERS_ATOMIC_CMPXCHG (0, sz, %ERI_PASTE (ERI_, creg) (sz), (%mem)))

#define ASM(creg, reg, cmem, mem) \
TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (ASM_SIZE, creg, reg, mem)

TST_FOREACH_GENERAL_REG2 (ASM)

static uint64_t val;

static struct tst_live_entry_mcontext ctrl_tctx;
static uint64_t ctrl_val;

static uint8_t
ctrl_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  ctrl_tctx = *tctx;
  ctrl_val = val;
  return 0;
}

static uint8_t
expr_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  eri_debug ("expr = %lx\n", tctx);
  eri_assert (tctx->rip == (uint64_t) args);
  tst_assert_live_entry_mcontext_eq (&ctrl_tctx, tctx,
				     ~TST_LIVE_ENTRY_MCONTEXT_RIP_MASK);
  eri_assert (val == ctrl_val);
  return 0;
}

struct tst_op
{
  const char *name;
  uint64_t mem_off;
  uint8_t rand;
  uint64_t mask;
  uint64_t rax; /* al, ax, eax, rax accordingly */
  uint64_t val; /* low bits only as rax */
  void *ctrl_enter, *expr_enter, *expr_leave;
};

static void
tst (struct tst_rand *rand, struct tst_op *op)
{
  /* eri_info ("%s %u %lx %lx\n", op->name, op->rand, op->rax, op->val); */

  struct tst_live_entry_mcontext tctx;
  tst_live_entry_rand_fill_mcontext (rand, &tctx);
  *(uint64_t **)((uint8_t *) &tctx + op->mem_off) = &val;

  uint64_t m = op->mask;
  if (! op->rand) tctx.rax = (tctx.rax & ~m) | (op->rax & m);
  uint64_t v = tst_rand_next (rand);
  if (! op->rand) v = (v & ~m) | (op->val & m);

  val = v;
  tctx.rip = (uint64_t) op->ctrl_enter;
  tst_live_entry (&tctx, ctrl_step, 0);

  val = v;
  tctx.rip = (uint64_t) op->expr_enter;
  tst_live_entry (&tctx, expr_step, op->expr_leave);
}

static unused struct tst_op tst_ops[] = {

#define MASK_b	0xff
#define MASK_w	0xffff
#define MASK_l	0xffffffff
#define MASK_q	0xffffffffffffffff

/* XXX: auto generate this */
#define _REG_IS_NOT_RAX_rax	0
#define _REG_IS_NOT_RAX_rbx	1
#define _REG_IS_NOT_RAX_rcx	1
#define _REG_IS_NOT_RAX_rdx	1
#define _REG_IS_NOT_RAX_rdi	1
#define _REG_IS_NOT_RAX_rsi	1
#define _REG_IS_NOT_RAX_rsp	1
#define _REG_IS_NOT_RAX_rbp	1
#define _REG_IS_NOT_RAX_r8	1
#define _REG_IS_NOT_RAX_r9	1
#define _REG_IS_NOT_RAX_r10	1
#define _REG_IS_NOT_RAX_r11	1
#define _REG_IS_NOT_RAX_r12	1
#define _REG_IS_NOT_RAX_r13	1
#define _REG_IS_NOT_RAX_r14	1
#define _REG_IS_NOT_RAX_r15	1

#define REG_IS_NOT_RAX(mem) ERI_PASTE (_REG_IS_NOT_RAX_, mem)

#define DO_TST_OP_SIZE(sz, reg, mem, rax, val) \
  { ERI_STR (OP (reg, mem, sz)),					\
    __builtin_offsetof (struct tst_live_entry_mcontext, mem),		\
    0, ERI_PASTE (MASK_, sz), rax, val,					\
    TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (OP (reg, mem, sz)),		\
    TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (OP (reg, mem, sz)),		\
    TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (OP (reg, mem, sz)) },

#define TST_OP_SIZE(sz, reg, mem, rax, val) \
  ERI_PP_IF (REG_IS_NOT_RAX (mem), DO_TST_OP_SIZE (sz, reg, mem, rax, val))

#define TST_OP(creg, reg, cmem, mem, rax, val) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (TST_OP_SIZE, reg, mem, rax, val)

  TST_FOREACH_GENERAL_REG2 (TST_OP, 0x123456789abcdef0, 0x123456789abcdef0)
  TST_FOREACH_GENERAL_REG2 (TST_OP, 0x123456789abcdef0, 0x123456789abcdef1)

#define TST_OP_RAND_SIZE(sz, reg, mem) \
  { ERI_STR (OP (reg, mem, sz)),					\
    __builtin_offsetof (struct tst_live_entry_mcontext, mem),		\
    1, 0, 0, 0,								\
    TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (OP (reg, mem, sz)),		\
    TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (OP (reg, mem, sz)),		\
    TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (OP (reg, mem, sz)) },

#define TST_OP_RAND(creg, reg, cmem, mem) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (TST_OP_RAND_SIZE, reg, mem)

  TST_FOREACH_GENERAL_REG2 (TST_OP_RAND)
};

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand);

#if 1
  uint16_t i;
  for (i = 0; i < eri_length_of (tst_ops); ++i)
    tst (&rand, tst_ops + i);
#else
  eri_global_enable_debug = 1;
  struct tst_op op[1] = {
    TST_OP_SIZE (l, rax, rax, 0x123456789abcdef0, 0x123456789abcdef0)
  };
  tst (&rand, op);
#endif

  eri_debug ("done\n");
  tst_assert_sys_exit (0);
}
