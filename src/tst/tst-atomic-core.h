#ifndef TST_TST_TST_ATOMIC_CORE_H
#define TST_TST_TST_ATOMIC_CORE_H

#include <lib/util.h>

#define __tst_atomic_load(e, sz, __m, __r) \
  ERS_ATOMIC_LOAD (e, sz, __m, __r)

#define __tst_atomic_store(e, sz, __r, __m) \
  ERS_ATOMIC_STORE (e, sz, __r, __m)

#define __tst_atomic_inc(e, sz, __m) \
  ERS_ATOMIC_INC (e, sz, __m)

#define __tst_atomic_dec(e, sz, __m) \
  ERS_ATOMIC_DEC (e, sz, __m)

#define __tst_atomic_add(e, sz, __r, __m) \
  ERS_ATOMIC_ADD (e, sz, __r, __m)

#define __tst_atomic_SUB(e, sz, __r, __m) \
  ERS_ATOMIC_SUB (e, sz, __r, __m)

#define __tst_atomic_ADC(e, sz, __r, __m) \
  ERS_ATOMIC_ADC (e, sz, __r, __m)

#define __tst_atomic_sbb(e, sz, __r, __m) \
  ERS_ATOMIC_SBB (e, sz, __r, __m)

#define __tst_atomic_neg(e, sz, __m) \
  ERS_ATOMIC_NEG (e, sz, __m)

#define __tst_atomic_and(e, sz, __r, __m) \
  ERS_ATOMIC_AND (e, sz, __r, __m)

#define __tst_atomic_or(e, sz, __r, __m) \
  ERS_ATOMIC_OR (e, sz, __r, __m)

#define __tst_atomic_xor(e, sz, __r, __m) \
  ERS_ATOMIC_XOR (e, sz, __r, __m)

#define __tst_atomic_not(e, sz, __m) \
  ERS_ATOMIC_NOT (e, sz, __m)

#define __tst_atomic_btc(e, sz, __r, __m) \
  ERS_ATOMIC_BTC (e, sz, __r, __m)

#define __tst_atomic_btr(e, sz, __r, __m) \
  ERS_ATOMIC_BTR (e, sz, __r, __m)

#define __tst_atomic_bts(e, sz, __r, __m) \
  ERS_ATOMIC_BTS (e, sz, __r, __m)

#define __tst_atomic_xadd(e, sz, __r, __m) \
  ERS_ATOMIC_XADD (e, sz, __r, __m)

#define __tst_atomic_xchg(e, sz, __r, __m) \
  ERS_ATOMIC_XCHG (e, sz, __r, __m)

#define __tst_atomic_cmpxchg(e, sz, __r, __m) \
  ERS_ATOMIC_CMPXCHG (e, sz, __r, __m)

#endif
