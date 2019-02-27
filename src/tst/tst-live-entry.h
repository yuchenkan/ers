#ifndef ERI_TST_TST_LIVE_ENTRY_H
#define ERI_TST_TST_LIVE_ENTRY_H

#include <stdint.h>

#include <lib/tst-util.h>
#include <tst/tst-util.h>

#include <tst/generated/registers.h>

#define TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG(p, ...) \
  TST_FOREACH_GENERAL_REG (p, ##__VA_ARGS__)				\
  p (RIP, rip, ##__VA_ARGS__)						\
  p (RFLAGS, rflags, ##__VA_ARGS__)

struct tst_live_entry_mcontext
{
#define _TST_LIVE_ENTRY_MCONTEXT_REG(cr, r)	uint64_t r;
  TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (_TST_LIVE_ENTRY_MCONTEXT_REG)
};

#define tst_live_entry_rand_fill_mcontext(rand, tctx) \
  do {									\
    struct tst_rand *_rand = rand;					\
    struct tst_live_entry_mcontext *_tctx = tctx;			\
    tst_rand_fill (_rand, _tctx, sizeof *_tctx);			\
    _tctx->rflags &= TST_RFLAGS_STATUS_MASK;				\
  } while (0);

void tst_live_entry (struct tst_live_entry_mcontext *ctx,
		uint8_t (*step) (struct tst_live_entry_mcontext *, void *),
		void *args);

enum
{
#define _TST_LIVE_ENTRY_MCONTEXT_REP_BIT_OFFSET(cr, r) \
  ERI_PASTE2 (TST_LIVE_ENTRY_MCONTEXT_, cr, _BIT_OFFSET),
  TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (
				_TST_LIVE_ENTRY_MCONTEXT_REP_BIT_OFFSET)
};

enum
{
#define _TST_LIVE_ENTRY_MCONTEXT_REP_MASK(cr, r) \
  ERI_PASTE2 (TST_LIVE_ENTRY_MCONTEXT_, cr, _MASK)			\
		= 1 << ERI_PASTE2 (TST_LIVE_ENTRY_MCONTEXT_, cr, _BIT_OFFSET),
  TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (
				_TST_LIVE_ENTRY_MCONTEXT_REP_MASK)
};

#define _TST_LIVE_ENTRY_MCONTEXT_ASSERT_REG_EQ(cr, r) \
  if (ERI_PASTE2 (TST_LIVE_ENTRY_MCONTEXT_, cr, _MASK) & _mask)	\
    eri_assert (_a->r == _b->r);

#define tst_assert_live_entry_mcontext_eq(a, b, mask) \
  do {									\
    struct tst_live_entry_mcontext *_a = a;				\
    struct tst_live_entry_mcontext *_b = b;				\
    uint32_t _mask = mask;						\
    TST_LIVE_ENTRY_MCONTEXT_FOREACH_REG (				\
			_TST_LIVE_ENTRY_MCONTEXT_ASSERT_REG_EQ)		\
  } while (0)

#endif
