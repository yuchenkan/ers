#include <common.h>

#include <public/impl.h>
#include <lib/util.h>
#include <lib/registers.h>
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

static struct tst_live_entry_atomic_case cases[] = {

#define INFO	0 // tst_live_entry_atomic_common_info

#define CASE_SIZE(sz, src, dst) \
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (src, dst, sz), dst, INFO, 0),

#define CASE_IMM_SIZE(sz, dst) \
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (imm, dst, sz), dst, INFO, 0),

#define CASE(csrc, src, cdst, dst) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (CASE_SIZE, src, dst)

#define CASE_IMM(cdst, dst) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE3 (CASE_IMM_SIZE, dst)

  TST_FOREACH_GENERAL_REG2 (CASE)
  TST_FOREACH_GENERAL_REG (CASE_IMM)
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0)
