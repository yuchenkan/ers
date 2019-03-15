#include <public.h>
#include <common.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <live/tst/tst-registers.h>
#include <live/tst/tst-entry-atomic.h>

#define OP(reg, mem, sz) \
  ERI_PASTE (ERI_PASTE2 (xchg_, reg, _), ERI_PASTE2 (mem, _, sz))

#define ASM_SIZE(sz, creg, reg, mem) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (reg, mem, sz),				\
	ERI_EVAL (ERI_PASTE (xchg, sz)	%ERI_PASTE (ERI_, creg) (sz),	\
					(%mem)),			\
	ERS_ATOMIC_XCHG (0, sz, %ERI_PASTE (ERI_, creg) (sz), (%mem)))

#define ASM(creg, reg, cmem, mem) \
ERI_FOREACH_REG_SIZE (ASM_SIZE, creg, reg, mem)

TST_FOREACH_GENERAL_REG2 (ASM)

static struct tst_live_entry_atomic_case cases[] = {

#define INFO	0 // tst_live_entry_atomic_common_info

#define CASE_SIZE(sz, reg, mem) \
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (reg, mem, sz), mem, INFO, 0),	\
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (OP (reg, mem, sz), mem, INFO),

#define CASE(creg, reg, cmem, mem) \
  ERI_FOREACH_REG_SIZE (CASE_SIZE, reg, mem)

  TST_FOREACH_GENERAL_REG2 (CASE)
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0)
