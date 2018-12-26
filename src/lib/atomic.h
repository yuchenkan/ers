#ifndef ERI_LIB_ATOMIC_H
#define ERI_LIB_ATOMIC_H

#include <stdint.h>

#include "public/common.h"
#include "lib/util.h"

#define eri_barrier()			asm volatile ("" : : : "memory");

#define eri_atomic_load(m)		(*(m))
#define eri_atomic_store(m, v)		do { *(m) = v; } while (0)

#define _eri_atomic_inc_dec(m, inc) \
  do {									\
    typeof (m) __m = m;							\
    if (sizeof *__m == 1)						\
      asm volatile ("lock " _ERS_STR (inc) "b\t%b0"			\
		    : "+m" (*__m) : : "cc");				\
    else if (sizeof *__m == 2)						\
      asm volatile ("lock " _ERS_STR (inc) "w\t%w0"			\
		    : "+m" (*__m) : : "cc");				\
    else if (sizeof *__m == 4)						\
      asm volatile ("lock " _ERS_STR (inc) "l\t%0"			\
		    : "+m" (*__m) : : "cc");				\
    else if (sizeof *__m == 8)						\
      asm volatile ("lock " _ERS_STR (inc) "q\t%q0"			\
		    : "+m" (*__m) : : "cc");				\
    else eri_assert (0);						\
  } while (0)

#define eri_atomic_inc(m)	_eri_atomic_inc_dec (m, inc)
#define eri_atomic_dec(m)	_eri_atomic_inc_dec (m, dec)

#define eri_atomic_add_fetch(m, v) \
  ({									\
    typeof (m) __m = m;							\
    typeof (*__m) __v = v;						\
    typeof (*__m) __r = __v;						\
    if (sizeof *__m == 1)						\
      asm volatile ("lock xaddb\t%b0, %1"				\
		    : "+r" (__r), "+m" (*__m) : : "cc");		\
    else if (sizeof *__m == 2)						\
      asm volatile ("lock xaddw\t%w0, %1"				\
		    : "+r" (__r), "+m" (*__m) : : "cc");		\
    else if (sizeof *__m == 4)						\
      asm volatile ("lock xaddl\t%0, %1"				\
		    : "+r" (__r), "+m" (*__m) : : "cc");		\
    else if (sizeof *__m == 8)						\
      asm volatile ("lock xaddq\t%q0, %1"				\
		    : "+r" (__r), "+m" (*__m) : : "cc");		\
    else eri_assert (0);						\
    (typeof (*__m)) (__r + __v);					\
  })

#define eri_atomic_inc_fetch(m)	eri_atomic_add_fetch (m, 1)
#define eri_atomic_dec_fetch(m) eri_atomic_add_fetch (m, -1)

#define eri_atomic_and(m, v) \
  do {									\
    typeof (m) __m = m;							\
    typeof (*__m) __v = (typeof (*__m)) v;				\
    if (sizeof *__m == 1)						\
      asm volatile ("lock andb\t%b1, %0"				\
		    : "+m" (*__m) : "ir" (__v) : "cc");			\
    else if (sizeof *__m == 2)						\
      asm volatile ("lock andw\t%w1, %0"				\
		    : "+m" (*__m) : "ir" (__v) : "cc");			\
    else if (sizeof *__m == 4)						\
      asm volatile ("lock andl\t%1, %0"					\
		    : "+m" (*__m) : "ir" (__v) : "cc");			\
    else if (sizeof *__m == 8)						\
      asm volatile ("lock andq\t%q1, %0"				\
		    : "+m" (*__m) : "r" (__v) : "cc");			\
    else eri_assert (0);						\
  } while (0)

#define eri_atomic_bit_test_set(m, off) \
  ({									\
    typeof (m) __m = m;							\
    typeof (off) _off = off;						\
    uint8_t __r;							\
    if (sizeof *__m == 2)						\
      asm volatile ("lock btsw\t%w2, %1"				\
		    : "=@ccc" (__r), "+m" (*__m) : "ir" (_off));	\
    else if (sizeof *__m == 4)						\
      asm volatile ("lock btsl\t%2, %1"					\
		    : "=@ccc" (__r), "+m" (*__m) : "ir" (_off));	\
    else if (sizeof *__m == 8)						\
      asm volatile ("lock btsq\t%q2, %1"				\
		    : "=@ccc" (__r), "+m" (*__m) : "ir" (_off));	\
    else eri_assert (0);						\
    __r;								\
  })

#define eri_atomic_exchange(m, v) \
  ({									\
    typeof (m) __m = m;							\
    typeof (*__m) __r = (typeof (*__m)) v;				\
    if (sizeof *__m == 1)						\
      asm volatile ("xchgb\t%b0, %1" : "+r" (__r), "+m" (*__m));	\
    else if (sizeof *__m == 2)						\
      asm volatile ("xchgw\t%w0, %1" : "+r" (__r), "+m" (*__m));	\
    else if (sizeof *__m == 4)						\
      asm volatile ("xchgl\t%0, %1" : "+r" (__r), "+m" (*__m));		\
    else if (sizeof *__m == 8)						\
      asm volatile ("xchgq\t%q0, %1" : "+r" (__r), "+m" (*__m));	\
    else eri_assert (0);						\
    __r;								\
  })

#define eri_atomic_compare_exchange(m, e, d) \
  ({									\
    typeof (m) __m = m;							\
    typeof (*__m) __e = (typeof (*__m)) e;				\
    typeof (*__m) __d = (typeof (*__m)) d;				\
    uint8_t __r;							\
    if (sizeof *__m == 1)						\
      asm volatile ("lock cmpxchgb\t%b3, %1"				\
		    : "=@ccz" (__r), "+m" (*__m)			\
		    : "a" (__e), "r" (__d));				\
    else if (sizeof *__m == 2)						\
      asm volatile ("lock cmpxchgw\t%w3, %1"				\
		    : "=@ccz" (__r), "+m" (*__m)			\
		    : "a" (__e), "r" (__d));				\
    else if (sizeof *__m == 4)						\
      asm volatile ("lock cmpxchgl\t%3, %1"				\
		    : "=@ccz" (__r), "+m" (*__m)			\
		    : "a" (__e), "r" (__d));				\
    else if (sizeof *__m == 8)						\
      asm volatile ("lock cmpxchgq\t%q3, %1"				\
		    : "=@ccz" (__r), "+m" (*__m)			\
		    : "a" (__e), "r" (__d));				\
    else eri_assert (0);						\
    __r;								\
  })

#define eri_catomic_load(mt, m)		eri_atomic_load (m)
#define eri_catomic_store(mt, m, v)	eri_atomic_store (m, v)

#define eri_catomic_inc(mt, m) \
  do { typeof (m) _m = m;						\
       if (mt) eri_atomic_inc (_m); else ++*_m; } while (0)
#define eri_catomic_dec(mt, m) \
  do { typeof (m) _m = m;						\
       if (mt) eri_atomic_dec (_m); else --*_m; } while (0)

#define eri_catomic_inc_fetch(mt, m) \
  ({ typeof (m) _m = m; (mt) ? eri_atomic_inc_fetch (_m) : ++*_m; })
#define eri_catomic_dec_fetch(mt, m) \
  ({ typeof (m) _m = m; (mt) ? eri_atomic_dec_fetch (_m) : --*_m; })

#endif
