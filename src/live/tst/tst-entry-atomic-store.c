#include <public.h>
#include <common.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <live/tst/tst-registers.h>
#include <live/tst/tst-entry-atomic.h>

#define OP(src, dst, sz) \
  ERI_PASTE (ERI_PASTE2 (store_, src, _), ERI_PASTE2 (dst, _, sz))

#define ASM_SIZE(sz, csrc, src, dst) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (src, dst, sz),				\
	ERI_EVAL (ERI_PASTE (mov, sz)	%ERI_PASTE (ERI_, csrc) (sz),	\
					(%dst)),			\
	ERS_ATOMIC_STORE (0, sz, %ERI_PASTE (ERI_, csrc) (sz), (%dst)))

#define ASM(csrc, src, cdst, dst) \
ERI_FOREACH_REG_SIZE (ASM_SIZE, csrc, src, dst)

TST_FOREACH_GENERAL_REG2 (ASM)

#define IMM_b	$0x12
#define IMM_w	$0x1234
#define IMM_l	$0x12345678

#define ASM_IMM_SIZE(sz, dst) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (imm, dst, sz),				\
	ERI_EVAL (ERI_PASTE (mov, sz)	ERI_PASTE (IMM_, sz), (%dst)),	\
	ERS_ATOMIC_STORE (0, sz, ERI_PASTE (IMM_, sz), (%dst)))

#define ASM_IMM(cdst, dst) \
ERI_FOREACH_REG_SIZE3 (ASM_IMM_SIZE, dst)

TST_FOREACH_GENERAL_REG (ASM_IMM)

static struct tst_live_entry_atomic_case cases[] = {

#define INFO	0 // tst_live_entry_atomic_common_info

#define CASE_SIZE(sz, src, dst) \
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (src, dst, sz), dst, INFO, 0),	\
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (OP (src, dst, sz), dst, INFO),

#define CASE_IMM_SIZE(sz, dst) \
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (imm, dst, sz), dst, INFO, 0),	\
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (OP (imm, dst, sz), dst, INFO),

#define CASE(csrc, src, cdst, dst) \
  ERI_FOREACH_REG_SIZE (CASE_SIZE, src, dst)

#define CASE_IMM(cdst, dst) \
  ERI_FOREACH_REG_SIZE3 (CASE_IMM_SIZE, dst)

  TST_FOREACH_GENERAL_REG2 (CASE)
  TST_FOREACH_GENERAL_REG (CASE_IMM)
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0, 0)
