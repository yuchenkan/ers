#ifndef TST_TST_TST_ATOMIC_CORE_H
#define TST_TST_TST_ATOMIC_CORE_H

#include <lib/util.h>

#define __tst_atomic_load(e, sz, __m, __r) \
  ERS_ATOMIC_LOAD (e, sz, __m, __r)

#define __tst_atomic_store(e, sz, __r, __m) \
  ERS_ATOMIC_STORE (e, sz, __r, __m)

#define ___tst_atomic_inc_dec(e, sz, __m, cinc, inc) \
  ERI_PASTE (ERS_ATOMIC_, cinc) (e, sz, __m)

#define __tst_atomic_and(e, sz, __r, __m) \
  ERS_ATOMIC_AND (e, sz, __r, __m)

#define __tst_atomic_or(e, sz, __r, __m) \
  ERS_ATOMIC_OR (e, sz, __r, __m)

#define __tst_atomic_xor(e, sz, __r, __m) \
  ERS_ATOMIC_XOR (e, sz, __r, __m)

#define __tst_atomic_xadd(e, sz, __r, __m) \
  ERS_ATOMIC_XADD (e, sz, __r, __m)

#define __tst_atomic_xchg(e, sz, __r, __m) \
  ERS_ATOMIC_XCHG (e, sz, __r, __m)

#define __tst_atomic_cmpxchg(e, sz, __r, __m) \
  ERS_ATOMIC_CMPXCHG (e, sz, __r, __m)

#endif
