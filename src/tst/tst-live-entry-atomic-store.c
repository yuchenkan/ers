#include <compiler.h>
#include <common.h>

#include <public/impl.h>
#include <lib/util.h>
#include <lib/registers.h>
#include <tst/tst-syscall.h>
#include <tst/tst-live-entry-atomic.h>
#include <tst/generated/registers.h>

#define OP(src, dst, sz) \
  ERI_PASTE (ERI_PASTE2 (store_, src, _), ERI_PASTE2 (dst, _, sz))

#define ASM_SIZE(sz, csrc, src, dst) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (src, dst, sz),				\
	ERI_EVAL (ERI_PASTE (mov, sz)	%ERI_PASTE (ERI_, csrc) (sz),	\
					(%dst)),			\
	_ERS_ATOMIC_STORE (0, sz, %ERI_PASTE (ERI_, csrc) (sz), (%dst)))

#define ASM(csrc, src, cdst, dst) \
TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (ASM_SIZE, csrc, src, dst)

TST_FOREACH_GENERAL_REG2 (ASM)

#define IMM_b	$0x12
#define IMM_w	$0x1234
#define IMM_l	$0x12345678

#define ASM_IMM_SIZE(sz, dst) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (imm, dst, sz),				\
	ERI_EVAL (ERI_PASTE (mov, sz)	ERI_PASTE (IMM_, sz), (%dst)),	\
	_ERS_ATOMIC_STORE (0, sz, ERI_PASTE (IMM_, sz), (%dst)))

#define ASM_IMM(cdst, dst) \
TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE3 (ASM_IMM_SIZE, dst)

TST_FOREACH_GENERAL_REG (ASM_IMM)

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
  uint64_t dst_off;
  void *ctrl_enter, *expr_enter, *expr_leave;
};

static void
tst (struct tst_rand *rand, struct tst_op *op)
{
  /* eri_info ("%s\n", op->name); */

  struct tst_live_entry_mcontext tctx;
  tst_live_entry_rand_fill_mcontext (rand, &tctx);
  *(uint64_t **)((uint8_t *) &tctx + op->dst_off) = &val;

  val = 0;
  tctx.rip = (uint64_t) op->ctrl_enter;
  tst_live_entry (&tctx, ctrl_step, 0);

  val = 0;
  tctx.rip = (uint64_t) op->expr_enter;
  tst_live_entry (&tctx, expr_step, op->expr_leave);
}

static unused struct tst_op tst_ops[] = {

#define TST_OP_SIZE(sz, src, dst) \
  { ERI_STR (OP (src, dst, sz)),					\
    __builtin_offsetof (struct tst_live_entry_mcontext, dst),		\
    TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (OP (src, dst, sz)),		\
    TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (OP (src, dst, sz)),		\
    TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (OP (src, dst, sz)) },

#define TST_OP(csrc, src, cdst, dst) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (TST_OP_SIZE, src, dst)

  TST_FOREACH_GENERAL_REG2 (TST_OP)

#define TST_OP_IMM_SIZE(sz, dst) \
  { ERI_STR (OP (imm, dst, sz)),					\
    __builtin_offsetof (struct tst_live_entry_mcontext, dst),		\
    TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (OP (imm, dst, sz)),		\
    TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (OP (imm, dst, sz)),		\
    TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (OP (imm, dst, sz)) },

#define TST_OP_IMM(cdst, dst) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE3 (TST_OP_IMM_SIZE, dst)

  TST_FOREACH_GENERAL_REG (TST_OP_IMM)
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
  struct tst_op op[1] = { TST_OP_SIZE (b, rbx, rax) };
  tst (&rand, op);
#endif

  eri_debug ("done\n");
  tst_assert_sys_exit (0);
}
