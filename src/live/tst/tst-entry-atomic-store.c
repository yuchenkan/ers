#include <public/public.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <common/debug.h>

#include <live/tst/tst-registers.h>
#include <live/tst/tst-entry-atomic.h>

#define ERS_ATOMIC_MOV(e, sz, r, m)	ERS_ATOMIC_STORE(e, sz, r, m)

TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT (MOV, mov)

#define NAME(reg, mem, sz) \
  TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT_NAME (mov, reg, mem, sz)

#define IMM_b	$0x12
#define IMM_w	$0x1234
#define IMM_l	$0x12345678

#define TEXT_IMM_SIZE(sz, dst) \
TST_LIVE_ENTRY_ATOMIC_TEXT (NAME (imm, dst, sz),			\
	ERI_EVAL (ERI_PASTE (mov, sz)	ERI_PASTE (IMM_, sz), (%dst)),	\
	ERS_ATOMIC_STORE (0, sz, ERI_PASTE (IMM_, sz), (%dst)))

#define TEXT_IMM(cdst, dst) \
ERI_FOREACH_REG_SIZE3 (TEXT_IMM_SIZE, dst)

TST_FOREACH_GENERAL_REG (TEXT_IMM)

static struct tst_live_entry_atomic_case cases[] = {

#define INFO	0 // tst_live_entry_atomic_common_info

#define CASE_SIZE(sz, src, dst) \
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT (NAME (src, dst, sz), dst, INFO, 0),	\
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (NAME (src, dst, sz), dst, INFO),

#define CASE_IMM_SIZE(sz, dst) \
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT (NAME (imm, dst, sz), dst, INFO, 0),	\
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (NAME (imm, dst, sz), dst, INFO),

#define CASE(csrc, src, cdst, dst) \
  ERI_FOREACH_REG_SIZE (CASE_SIZE, src, dst)

#define CASE_IMM(cdst, dst) \
  ERI_FOREACH_REG_SIZE3 (CASE_IMM_SIZE, dst)

  TST_FOREACH_GENERAL_REG2 (CASE)
  TST_FOREACH_GENERAL_REG (CASE_IMM)
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0, 0)
