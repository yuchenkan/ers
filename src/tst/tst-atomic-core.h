#ifndef TST_TST_ATOMIC_CORE_H
#define TST_TST_ATOMIC_CORE_H

#define __tst_atomic_load(e, sz, __m, __r) \
  ERS_ATOMIC_LOAD (e, sz, __m, __r)

#define __tst_atomic_store(e, sz, __r, __m) \
  ERS_ATOMIC_STORE (e, sz, __r, __m)

#endif
