#ifndef ERI_LIB_ATOMIC_H
#define ERI_LIB_ATOMIC_H

#include <stdint.h>

#include "lib/util.h"

#define eri_barrier()			asm volatile ("" : : : "memory")

#define eri_atomic_load(m)		(*(m))
#define eri_atomic_store(m, v)		do { *(m) = v; } while (0)

#define eri_atomic_load_acq(m) \
  ({ typeof (*m) _v = eri_atomic_load (m); eri_barrier (); _v; })
#define eri_atomic_store_rel(m, v) \
  do { eri_barrier (); eri_atomic_store (m, v); } while (0)

#define _eri_atomic_inc_dec(m, inc) \
  do {									\
    typeof (m) _m = m;							\
    if (sizeof *_m == 1)						\
      asm volatile ("lock " ERI_STR (inc) "b\t%b0"			\
		    : "+m" (*_m) : : "cc");				\
    else if (sizeof *_m == 2)						\
      asm volatile ("lock " ERI_STR (inc) "w\t%w0"			\
		    : "+m" (*_m) : : "cc");				\
    else if (sizeof *_m == 4)						\
      asm volatile ("lock " ERI_STR (inc) "l\t%0"			\
		    : "+m" (*_m) : : "cc");				\
    else if (sizeof *_m == 8)						\
      asm volatile ("lock " ERI_STR (inc) "q\t%q0"			\
		    : "+m" (*_m) : : "cc");				\
    else eri_assert (0);						\
  } while (0)

#define eri_atomic_inc(m)	_eri_atomic_inc_dec (m, inc)
#define eri_atomic_dec(m)	_eri_atomic_inc_dec (m, dec)

#define eri_atomic_add_fetch(m, v) \
  ({									\
    typeof (m) _m = m;							\
    typeof (*_m) _v = v;						\
    typeof (*_m) _r = _v;						\
    if (sizeof *_m == 1)						\
      asm volatile ("lock xaddb\t%b0, %1"				\
		    : "+r" (_r), "+m" (*_m) : : "cc");			\
    else if (sizeof *_m == 2)						\
      asm volatile ("lock xaddw\t%w0, %1"				\
		    : "+r" (_r), "+m" (*_m) : : "cc");			\
    else if (sizeof *_m == 4)						\
      asm volatile ("lock xaddl\t%0, %1"				\
		    : "+r" (_r), "+m" (*_m) : : "cc");			\
    else if (sizeof *_m == 8)						\
      asm volatile ("lock xaddq\t%q0, %1"				\
		    : "+r" (_r), "+m" (*_m) : : "cc");			\
    else eri_assert (0);						\
    (typeof (*_m)) (_r + _v);						\
  })

#define eri_atomic_inc_fetch(m)	eri_atomic_add_fetch (m, 1)
#define eri_atomic_dec_fetch(m) eri_atomic_add_fetch (m, -1)

#define eri_atomic_fetch_inc(m) (eri_atomic_inc_fetch (m) - 1)

#define eri_atomic_dec_fetch_rel(m) \
  ({ eri_barrier (); eri_atomic_dec_fetch (m); })

#define eri_atomic_and(m, v) \
  do {									\
    typeof (m) _m = m;							\
    typeof (*_m) _v = (typeof (*_m)) v;					\
    if (sizeof *_m == 1)						\
      asm volatile ("lock andb\t%b1, %0"				\
		    : "+m" (*_m) : "ir" (_v) : "cc");			\
    else if (sizeof *_m == 2)						\
      asm volatile ("lock andw\t%w1, %0"				\
		    : "+m" (*_m) : "ir" (_v) : "cc");			\
    else if (sizeof *_m == 4)						\
      asm volatile ("lock andl\t%1, %0"					\
		    : "+m" (*_m) : "ir" (_v) : "cc");			\
    else if (sizeof *_m == 8)						\
      asm volatile ("lock andq\t%q1, %0"				\
		    : "+m" (*_m) : "r" (_v) : "cc");			\
    else eri_assert (0);						\
  } while (0)

#define eri_atomic_bit_test_set(m, off) \
  ({									\
    typeof (m) _m = m;							\
    typeof (off) _off = off;						\
    uint8_t _r;								\
    if (sizeof *_m == 2)						\
      asm volatile ("lock btsw\t%w2, %1"				\
		    : "=@ccc" (_r), "+m" (*_m) : "ir" (_off));		\
    else if (sizeof *_m == 4)						\
      asm volatile ("lock btsl\t%2, %1"					\
		    : "=@ccc" (_r), "+m" (*_m) : "ir" (_off));		\
    else if (sizeof *_m == 8)						\
      asm volatile ("lock btsq\t%q2, %1"				\
		    : "=@ccc" (_r), "+m" (*_m) : "ir" (_off));		\
    else eri_assert (0);						\
    _r;									\
  })

#define eri_atomic_exchange(m, v) \
  ({									\
    typeof (m) _m = m;							\
    typeof (*_m) _r = (typeof (*_m)) v;					\
    if (sizeof *_m == 1)						\
      asm volatile ("xchgb\t%b0, %1" : "+r" (_r), "+m" (*_m));		\
    else if (sizeof *_m == 2)						\
      asm volatile ("xchgw\t%w0, %1" : "+r" (_r), "+m" (*_m));		\
    else if (sizeof *_m == 4)						\
      asm volatile ("xchgl\t%0, %1" : "+r" (_r), "+m" (*_m));		\
    else if (sizeof *_m == 8)						\
      asm volatile ("xchgq\t%q0, %1" : "+r" (_r), "+m" (*_m));		\
    else eri_assert (0);						\
    _r;									\
  })

#define eri_atomic_compare_exchange(m, e, d) \
  ({									\
    typeof (m) _m = m;							\
    typeof (*_m) _e = (typeof (*_m)) e;					\
    typeof (*_m) _d = (typeof (*_m)) d;					\
    uint8_t _r;								\
    if (sizeof *_m == 1)						\
      asm volatile ("lock cmpxchgb\t%b3, %1"				\
		    : "=@ccz" (_r), "+m" (*_m)				\
		    : "a" (_e), "r" (_d));				\
    else if (sizeof *_m == 2)						\
      asm volatile ("lock cmpxchgw\t%w3, %1"				\
		    : "=@ccz" (_r), "+m" (*_m)				\
		    : "a" (_e), "r" (_d));				\
    else if (sizeof *_m == 4)						\
      asm volatile ("lock cmpxchgl\t%3, %1"				\
		    : "=@ccz" (_r), "+m" (*_m)				\
		    : "a" (_e), "r" (_d));				\
    else if (sizeof *_m == 8)						\
      asm volatile ("lock cmpxchgq\t%q3, %1"				\
		    : "=@ccz" (_r), "+m" (*_m)				\
		    : "a" (_e), "r" (_d));				\
    else eri_assert (0);						\
    _r;									\
  })

#endif
