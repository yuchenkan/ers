#include <public/public.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <common/debug.h>

#include <live/tst/tst-registers.h>
#include <live/tst/tst-entry-atomic.h>

#define ERS_LOAD_CMP(sz, res, reg)	ERI_PASTE (cmp, sz)	reg, res

#define ERS_ATOMIC_CMP(e, sz, reg, mem) \
  ERS_ATOMIC_COMMON_LOAD (e, sz, mem, ERS_LOAD_CMP, reg)

TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT (CMP, cmp)

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

#define NAME(reg, mem, sz) \
  TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT_NAME (cmp, reg, mem, sz)

static struct caze cases[] = {

#define INFO	0 // tst_live_entry_atomic_common_info

#define CASE_SIZE(sz, reg, mem) \
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (NAME (reg, mem, sz),		\
				     mem, INFO, init),			\
    __builtin_offsetof (struct tst_live_entry_mcontext, reg) },		\
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (NAME (reg, mem, sz),		\
				     mem, INFO, 0) },			\
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (NAME (reg, mem, sz),		\
					   mem, INFO) },

#define CASE(creg, reg, cmem, mem) \
  ERI_FOREACH_REG_SIZE (CASE_SIZE, reg, mem)

  TST_FOREACH_GENERAL_REG2 (CASE)
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0, 0)
