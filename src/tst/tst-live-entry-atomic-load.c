#include <compiler.h>
#include <common.h>

#include <public/impl.h>
#include <lib/util.h>
#include <lib/registers.h>
#include <tst/tst-syscall.h>
#include <tst/tst-live-entry-atomic.h>
#include <tst/generated/registers.h>

#define OP(src, dst, sz) \
  ERI_PASTE (ERI_PASTE2 (load_, src, _), ERI_PASTE2 (dst, _, sz))

#define ASM_SIZE(sz, src, cdst, dst) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (src, dst, sz),				\
	ERI_EVAL (ERI_PASTE (mov, sz)	(%src),				\
					%ERI_PASTE (ERI_, cdst) (sz)),	\
	_ERS_ATOMIC_LOAD (0, sz, (%src), %ERI_PASTE (ERI_, cdst) (sz)))

#define ASM(csrc, src, cdst, dst) \
TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (ASM_SIZE, src, cdst, dst)

TST_FOREACH_GENERAL_REG2 (ASM)

#define VAL	0x123456789abcdef0
static uint64_t val = VAL;

static struct tst_live_entry_mcontext ctrl_tctx;

static uint8_t
ctrl_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  ctrl_tctx = *tctx;
  return 0;
}

static uint8_t
expr_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  eri_debug ("expr = %lx\n", tctx);
  eri_assert (tctx->rip == (uint64_t) args);
  tst_assert_live_entry_mcontext_eq (&ctrl_tctx, tctx,
				     ~TST_LIVE_ENTRY_MCONTEXT_RIP_MASK);
  eri_assert (val == VAL);
  return 0;
}

struct tst_op
{
  const char *name;
  uint64_t src_off;
  void *ctrl_enter, *expr_enter, *expr_leave;
};

static void
tst (struct tst_rand *rand, struct tst_op *op)
{
  /* eri_info ("%s\n", op->name); */

  struct tst_live_entry_mcontext tctx;
  tst_live_entry_rand_fill_mcontext (rand, &tctx);
  *(uint64_t **)((uint8_t *) &tctx + op->src_off) = &val;

  tctx.rip = (uint64_t) op->ctrl_enter;
  tst_live_entry (&tctx, ctrl_step, 0);

  tctx.rip = (uint64_t) op->expr_enter;
  tst_live_entry (&tctx, expr_step, op->expr_leave);
}

static unused struct tst_op tst_ops[] = {

#define TST_OP_SIZE(sz, src, dst) \
  { ERI_STR (OP (src, dst, sz)),					\
    __builtin_offsetof (struct tst_live_entry_mcontext, src),		\
    TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (OP (src, dst, sz)),		\
    TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (OP (src, dst, sz)),		\
    TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (OP (src, dst, sz)) },

#define TST_OP(csrc, src, cdst, dst) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (TST_OP_SIZE, src, dst)

  TST_FOREACH_GENERAL_REG2 (TST_OP)
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
