#ifndef ERI_LIB_ATOMIC_CORE_H
#define ERI_LIB_ATOMIC_CORE_H

#include <lib/util.h>

#define __eri_atomic_load(e, sz, __m, __r) \
  ERI_PASTE (mov, sz)	__m, __r

#define __eri_atomic_store(e, sz, __r, __m) \
  ERI_PASTE (mov, sz)	__r, __m

#define ___eri_atomic_inc_dec(e, sz, __m, cinc, inc) \
  lock ERI_PASTE (inc, sz)	__m

#define __eri_atomic_xadd(e, sz, __r, __m) \
  lock ERI_PASTE (xadd, sz)	__r, __m

#define __eri_atomic_add(e, sz, __r, __m) \
  lock ERI_PASTE (add, sz)	__r, __m

#define __eri_atomic_and(e, sz, __r, __m) \
  lock ERI_PASTE (and, sz)	__r, __m

#define __eri_atomic_or(e, sz, __r, __m) \
  lock ERI_PASTE (or, sz)	__r, __m

#define __eri_atomic_xor(e, sz, __r, __m) \
  lock ERI_PASTE (xor, sz)	__r, __m

#define __eri_atomic_xadd(e, sz, __r, __m) \
  lock ERI_PASTE (xadd, sz)	__r, __m

#define __eri_atomic_bts(e, sz, __off, __m) \
  lock ERI_PASTE (bts, sz)	__off, __m

#define __eri_atomic_xchg(e, sz, __r, __m) \
  ERI_PASTE (xchg, sz)	__r, __m

#define __eri_atomic_cmpxchg(e, sz, __r, __m) \
  lock ERI_PASTE (cmpxchg, sz)	__r, __m

#endif
