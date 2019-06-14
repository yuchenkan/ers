/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#ifndef m4_NS(LIB_ATOMIC_IMPL_H)
#define m4_NS(LIB_ATOMIC_IMPL_H)

#include <stdint.h>

#include <lib/util.h>
#include <lib/atomic-common.h>

#include <m4_atomic_core_h>

#define m4_ns(atomic_load, _)(sz, _m, _v, b) \
  asm volatile (ERI_STR (m4_ns(atomic_load, __) (1, sz,			\
				%1, %_ERI_ASM_TEMPLATE_SIZE (sz, 0)))	\
		: "=r" (_v) : "m" (*_m) ERI_PP_IF (b, : "memory"))
#define m4_ns(atomic_store, _)(sz, _m, _v, b) \
  asm volatile (ERI_STR (m4_ns(atomic_store, __) (1, sz,		\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 1), %0))	\
		: "=m" (*_m) : "r" (_v) ERI_PP_IF (b, : "memory"))

#define m4_ns(atomic_load)(m, b) \
  ({ typeof (m) _m = m;	typeof (*_m) _v;				\
     _eri_atomic_switch_size (_m, m4_ns(atomic_load, _), _v, b); _v; })
#define m4_ns(atomic_store)(m, v, b) \
  do { typeof (m) _m = m; typeof (*_m) _v = (typeof (*_m)) (v);		\
       _eri_atomic_switch_size (_m, m4_ns(atomic_store, _), _v, b); } while (0)

#define m4_ns(atomic_inc_dec, __)(sz, _m, b, cinc, inc) \
  asm volatile (ERI_STR (m4_ns(atomic_inc_dec, ___) (1, sz,		\
					 	     %0, cinc, inc))	\
		: "+m" (*_m) : : "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_inc_dec, _)(m, b, cinc, inc) \
  do {									\
    typeof (m) _m = m;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_inc_dec, __), b,		\
			     cinc, inc);				\
  } while (0)

#define m4_ns(atomic_inc)(m, b)	m4_ns(atomic_inc_dec, _) (m, b, INC, inc)
#define m4_ns(atomic_dec)(m, b)	m4_ns(atomic_inc_dec, _) (m, b, DEC, dec)

#define m4_ns(atomic_xadd, _)(sz, _m, _v, b) \
  asm volatile (ERI_STR (m4_ns(atomic_xadd, __) (1, sz,			\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 0), %1))	\
		: "+r" (_v), "+m" (*_m) : : "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_add_fetch)(m, v, b) \
  ({ typeof (m) _m = m;							\
     typeof (*_m) _v = (typeof (*_m)) (v);				\
     typeof (*_m) _r = _v;						\
     _eri_atomic_switch_size (_m, m4_ns(atomic_xadd, _), _v, b);	\
     (typeof (*_m)) (_r + _v); })

#define m4_ns(atomic_inc_fetch)(m, b)	m4_ns(atomic_add_fetch) (m, 1, b)
#define m4_ns(atomic_dec_fetch)(m, b)	m4_ns(atomic_add_fetch) (m, -1, b)

#define m4_ns(atomic_fetch_inc)(m, b)	(m4_ns(atomic_inc_fetch) (m, b) - 1)
#define m4_ns(atomic_fetch_dec)(m, b)	(m4_ns(atomic_dec_fetch) (m, b) + 1)

#define m4_ns(atomic_and, _)(sz, _m, _v, b) \
  asm volatile (ERI_STR (m4_ns(atomic_and, __) (1, sz,			\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 1), %0))	\
		: "+m" (*_m) : "r" (_v) : "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_and)(m, v, b) \
  do {									\
    typeof (m) _m = m;							\
    typeof (*_m) _v = (typeof (*_m)) (v);				\
    _eri_atomic_switch_size (_m, m4_ns(atomic_and, _), _v, b);		\
  } while (0)

#define m4_ns(atomic_bts, _)(sz, _m, _off, _r, b) \
  asm volatile (ERI_STR (m4_ns(atomic_bts, __) (1, sz,			\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 2), %1))	\
		: "=@ccc" (_r), "+m" (*_m) : "r" (_off)			\
		ERI_PP_IF (b, : "memory"))

#define m4_ns(atomic_bit_test_set)(m, off, b) \
  ({ typeof (m) _m = m;							\
     typeof (off) _off = off;						\
     uint8_t _r;							\
     _eri_atomic_switch_size1 (_m, m4_ns(atomic_bts, _), _off, _r, b);	\
     _r; })

#define m4_ns(atomic_xchg, _)(sz, _m, _r, b) \
  asm volatile (ERI_STR (m4_ns(atomic_xchg, __) (1, sz,			\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 0), %1))	\
		: "+r" (_r), "+m" (*_m) ERI_PP_IF (b, : : "memory"))

#define m4_ns(atomic_exchange)(m, v, b) \
  ({ typeof (m) _m = m;							\
     typeof (*_m) _r = (typeof (*_m)) (v);				\
     _eri_atomic_switch_size (_m, m4_ns(atomic_xchg, _), _r, b);	\
     _r; })

#define m4_ns(atomic_cmpxchg, _)(sz, _m, _r, _a, _s, b) \
  asm volatile (ERI_STR (m4_ns(atomic_cmpxchg, __) (1, sz,		\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 3), %1))	\
		: "=@ccz" (_r), "+m" (*_m) : "a" (_a), "r" (_s)		\
		ERI_PP_IF (b, : "memory"))

#define m4_ns(atomic_compare_exchange)(m, e, d, b) \
  ({ typeof (m) _m = m;							\
     typeof (*_m) _e = (typeof (*_m)) (e);				\
     typeof (*_m) _d = (typeof (*_m)) (d);				\
     uint8_t _r;							\
     _eri_atomic_switch_size (_m, m4_ns(atomic_cmpxchg, _),		\
			      _r, _e, _d, b);				\
     _r; })

#define m4_ns(atomic_inc_dec_x, __)(sz, _m, _f, b, cinc, inc) \
  asm volatile ("pushq\t%q0;popfq;"					\
		ERI_STR (m4_ns(atomic_inc_dec, ___) (1, sz,		\
						     %1, cinc, inc))	\
		";pushfq;popq\t%q0"					\
		: "+r" (*_f) : "m" (*_m) : "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_inc_dec_x, _)(m, f, b, cinc, inc) \
  do {									\
    typeof (m) _m = m;							\
    uint64_t *_f = f;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_inc_dec_x, __), _f, b,	\
			     cinc, inc);				\
  } while (0)

#define m4_ns(atomic_inc_x)(m, f, b) \
  m4_ns(atomic_inc_dec_x, _) (m, f, b, INC, inc)
#define m4_ns(atomic_dec_x)(m, f, b) \
  m4_ns(atomic_inc_dec_x, _) (m, f, b, DEC, dec)

#define m4_ns(atomic_cmpxchg_x, _)(sz, _m, _a, _s, _f, b) \
  asm volatile ("pushq\t%q0;popfq;"					\
		ERI_STR (m4_ns(atomic_cmpxchg, __) (1, sz,		\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 3), %2))	\
		";pushfq;popq\t%q0"					\
		: "+r" (*_f), "+a" (*_a) : "m" (*_m), "r" (_s)		\
		: "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_cmpxchg_x)(m, a, s, f, b) \
  do {									\
    typeof (m) _m = m;							\
    uint64_t *_a = a;							\
    typeof (*_m) _s = (typeof (*_m)) (s);				\
    uint64_t *_f = f;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_cmpxchg_x, _),		\
			     _a, _s, _f, b);				\
  } while (0)

#endif
