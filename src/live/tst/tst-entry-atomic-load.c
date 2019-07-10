#include <public/public.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <common/debug.h>

#include <live/tst/tst-registers.h>
#include <live/tst/tst-entry-atomic.h>

#define NAME(src, dst, sz) \
  ERI_PASTE (ERI_PASTE2 (load_, src, _), ERI_PASTE2 (dst, _, sz))

#define TEXT_SIZE(sz, src, cdst, dst) \
TST_LIVE_ENTRY_ATOMIC_TEXT (NAME (src, dst, sz),			\
	ERI_EVAL (ERI_PASTE (mov, sz)	(%src),				\
					%ERI_PASTE (ERI_, cdst) (sz)),	\
	ERS_ATOMIC_LOAD (0, sz, (%src), %ERI_PASTE (ERI_, cdst) (sz)))

#define TEXT(csrc, src, cdst, dst) \
ERI_FOREACH_REG_SIZE (TEXT_SIZE, src, cdst, dst)

TST_FOREACH_GENERAL_REG2 (TEXT)

static struct tst_live_entry_atomic_case cases[] = {

#define INFO	0 // tst_live_entry_atomic_common_info

#define CASE_SIZE(sz, src, dst) \
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT (NAME (src, dst, sz), src, INFO, 0),	\
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (NAME (src, dst, sz), src, INFO),

#if 1
#define CASE(csrc, src, cdst, dst) \
  ERI_FOREACH_REG_SIZE (CASE_SIZE, src, dst)

  TST_FOREACH_GENERAL_REG2 (CASE)
#else
  CASE_SIZE (b, rbx, rax)
#endif
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0, 0)
