#include <public.h>
#include <common.h>

#include <lib/util.h>
#include <lib/registers.h>
#include <tst/tst-live-entry-atomic.h>
#include <tst/generated/registers.h>

#define OP(src, dst, sz) \
  ERI_PASTE (ERI_PASTE2 (load_, src, _), ERI_PASTE2 (dst, _, sz))

#define ASM_SIZE(sz, src, cdst, dst) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (src, dst, sz),				\
	ERI_EVAL (ERI_PASTE (mov, sz)	(%src),				\
					%ERI_PASTE (ERI_, cdst) (sz)),	\
	ERS_ATOMIC_LOAD (0, sz, (%src), %ERI_PASTE (ERI_, cdst) (sz)))

#define ASM(csrc, src, cdst, dst) \
TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (ASM_SIZE, src, cdst, dst)

TST_FOREACH_GENERAL_REG2 (ASM)

static struct tst_live_entry_atomic_case cases[] = {

#define INFO	0 // tst_live_entry_atomic_common_info

#define CASE_SIZE(sz, src, dst) \
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (src, dst, sz), src, INFO, 0),	\
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (OP (src, dst, sz), src, INFO),	\

#if 1
#define CASE(csrc, src, cdst, dst) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (CASE_SIZE, src, dst)

  TST_FOREACH_GENERAL_REG2 (CASE)
#else
  CASE_SIZE (b, rbx, rax)
#endif
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0)
