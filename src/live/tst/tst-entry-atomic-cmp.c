#include <public.h>
#include <common.h>

#include <lib/util.h>
#include <lib/registers.h>
#include <live/tst/tst-registers.h>
#include <live/tst/tst-entry-atomic.h>

#define OP(reg, mem, sz) \
  ERI_PASTE (ERI_PASTE2 (cmp_, reg, _), ERI_PASTE2 (mem, _, sz))

#define ERI_LOAD_CMP(sz, res, reg)	ERI_PASTE (cmp, sz)	reg, res

#define ERI_ATOMIC_CMP(e, sz, reg, mem) \
  ERS_ATOMIC_COMMON_LOAD (e, sz, mem, ERI_LOAD_CMP, reg)

#define ASM_SIZE(sz, creg, reg, mem) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (reg, mem, sz),				\
	ERI_EVAL (ERI_PASTE (cmp, sz)	%ERI_PASTE (ERI_, creg) (sz),	\
					(%mem)),			\
	ERI_ATOMIC_CMP (0, sz, %ERI_PASTE (ERI_, creg) (sz), (%mem)))

#define ASM(creg, reg, cmem, mem) \
TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (ASM_SIZE, creg, reg, mem)

TST_FOREACH_GENERAL_REG2 (ASM)

struct caze
{
  struct tst_live_entry_atomic_case caze;
  uint64_t reg_off;
};

static void
init (struct tst_live_entry_mcontext *tctx, uint64_t *val,
      struct caze *caze)
{
  *val = *(uint64_t *) ((uint8_t *) tctx + caze->reg_off);
}

static struct caze cases[] = {

#define INFO	0 // tst_live_entry_atomic_common_info

#define CASE_SIZE(sz, reg, mem) \
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (reg, mem, sz),			\
				     mem, INFO, init),			\
    __builtin_offsetof (struct tst_live_entry_mcontext, reg) },		\
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (reg, mem, sz),			\
				     mem, INFO, 0) },			\
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (OP (reg, mem, sz),		\
					   mem, INFO) },

#define CASE(creg, reg, cmem, mem) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (CASE_SIZE, reg, mem)

  TST_FOREACH_GENERAL_REG2 (CASE)
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0)
