/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#include <stdint.h>

#include <lib/util.h>
#include <lib/atomic-common.h>

#include <m4_atomic_core_h>

#define m4_ns(atomic_load, _)(sz, _m, _v) \
  asm volatile (ERI_STR (m4_ns(atomic_load, __) (1, sz,			\
				%1, %_ERI_ASM_TEMPLATE_SIZE (sz, 0)))	\
		: "=r" (_v) : "m" (*_m))
#define m4_ns(atomic_store, _)(sz, _m, _v) \
  asm volatile (ERI_STR (m4_ns(atomic_store, __) (1, sz,		\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 1), %0))	\
		: "=m" (*_m) : "r" (_v))

#define m4_ns(atomic_load)(m) \
  ({ typeof (m) _m = m;	typeof (*_m) _v;				\
     _eri_atomic_switch_size (_m, m4_ns(atomic_load, _), _v); _v; })
#define m4_ns(atomic_store)(m, v) \
  do { typeof (m) _m = m; typeof (*_m) _v = (typeof (*_m)) (v);		\
       _eri_atomic_switch_size (_m, m4_ns(atomic_store, _), _v); } while (0)

#define m4_ns(atomic_load_acq)(m) \
  ({ typeof (*m) _v = m4_ns(atomic_load) (m); eri_barrier (); _v; })
#define m4_ns(atomic_store_rel)(m, v) \
  do { eri_barrier (); m4_ns(atomic_store) (m, v); } while (0)

#define m4_ns(atomic_inc_dec, __)(sz, _m, cinc, inc) \
  asm volatile (ERI_STR (m4_ns(atomic_inc_dec, ___) (1, sz,		\
					 	     %0, cinc, inc))	\
		: "+m" (*_m) : : "cc")

#define m4_ns(atomic_inc_dec, _)(m, cinc, inc) \
  do {									\
    typeof (m) _m = m;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_inc_dec, __),		\
			     cinc, inc);				\
  } while (0)

#define m4_ns(atomic_inc)(m)	m4_ns(atomic_inc_dec, _) (m, INC, inc)
#define m4_ns(atomic_dec)(m)	m4_ns(atomic_inc_dec, _) (m, DEC, dec)

#define m4_ns(atomic_xadd, _)(sz, _m, _v) \
  asm volatile (ERI_STR (m4_ns(atomic_xadd, __) (1, sz,			\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 0), %1))	\
		: "+r" (_v), "+m" (*_m) : : "cc")

#define m4_ns(atomic_add_fetch)(m, v) \
  ({ typeof (m) _m = m;							\
     typeof (*_m) _v = (typeof (*_m)) (v);				\
     typeof (*_m) _r = _v;						\
     _eri_atomic_switch_size (_m, m4_ns(atomic_xadd, _), _v);		\
     (typeof (*_m)) (_r + _v); })

#define m4_ns(atomic_inc_fetch)(m)	m4_ns(atomic_add_fetch) (m, 1)
#define m4_ns(atomic_dec_fetch)(m)	m4_ns(atomic_add_fetch) (m, -1)

#define m4_ns(atomic_fetch_inc)(m)	(m4_ns(atomic_inc_fetch) (m) - 1)
#define m4_ns(atomic_fetch_dec)(m)	(m4_ns(atomic_dec_fetch) (m) + 1)

#define m4_ns(atomic_inc_fetch_rel)(m) \
  ({ eri_barrier (); m4_ns(atomic_inc_fetch) (m); })
#define m4_ns(atomic_dec_fetch_rel)(m) \
  ({ eri_barrier (); m4_ns(atomic_dec_fetch) (m); })

#define m4_ns(atomic_and, _)(sz, _m, _v) \
  asm volatile (ERI_STR (m4_ns(atomic_and, __) (1, sz,			\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 1), %0))	\
		: "+m" (*_m) : "r" (_v) : "cc")

#define m4_ns(atomic_and)(m, v) \
  do {									\
    typeof (m) _m = m;							\
    typeof (*_m) _v = (typeof (*_m)) (v);				\
    _eri_atomic_switch_size (_m, m4_ns(atomic_and, _), _v);		\
  } while (0)

#define m4_ns(atomic_bts, _)(sz, _m, _off, _r) \
  asm volatile (ERI_STR (m4_ns(atomic_bts, __) (1, sz,			\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 2), %1))	\
		: "=@ccc" (_r), "+m" (*_m) : "r" (_off))

#define m4_ns(atomic_bit_test_set)(m, off) \
  ({ typeof (m) _m = m;							\
     typeof (off) _off = off;						\
     uint8_t _r;							\
     _eri_atomic_switch_size1 (_m, m4_ns(atomic_bts, _), _off, _r);	\
     _r; })

#define m4_ns(atomic_xchg, _)(sz, _m, _r) \
  asm volatile (ERI_STR (m4_ns(atomic_xchg, __) (1, sz,			\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 0), %1))	\
		: "+r" (_r), "+m" (*_m))

#define m4_ns(atomic_exchange)(m, v) \
  ({ typeof (m) _m = m;							\
     typeof (*_m) _r = (typeof (*_m)) (v);				\
     _eri_atomic_switch_size (_m, m4_ns(atomic_xchg, _), _r);		\
     _r; })

#define m4_ns(atomic_cmpxchg, _)(sz, _m, _r, _a, _s) \
  asm volatile (ERI_STR (m4_ns(atomic_cmpxchg, __) (1, sz,		\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 3), %1))	\
		:  "=@ccz" (_r), "+m" (*_m) : "a" (_a), "r" (_s))

#define m4_ns(atomic_compare_exchange)(m, e, d) \
  ({ typeof (m) _m = m;							\
     typeof (*_m) _e = (typeof (*_m)) (e);				\
     typeof (*_m) _d = (typeof (*_m)) (d);				\
     uint8_t _r;							\
     _eri_atomic_switch_size (_m, m4_ns(atomic_cmpxchg, _),		\
			      _r, _e, _d);				\
     _r; })

#define m4_ns(atomic_inc_dec_x, __)(sz, _m, _f, cinc, inc) \
  asm volatile ("pushq\t%q1;popfq;"					\
		ERI_STR (m4_ns(atomic_inc_dec, ___) (1, sz,		\
						     %0, cinc, inc))	\
		";pushfq;popq\t%q1"					\
		: "+m" (*_m), "+r" (*_f) : : "cc", "memory")

#define m4_ns(atomic_inc_dec_x, _)(m, f, cinc, inc) \
  do {									\
    typeof (m) _m = m;							\
    uint64_t *_f = f;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_inc_dec_x, __), _f,	\
			     cinc, inc);				\
  } while (0)

#define m4_ns(atomic_inc_x)(m, f) \
  m4_ns(atomic_inc_dec_x, _) (m, f, INC, inc)
#define m4_ns(atomic_dec_x)(m, f) \
  m4_ns(atomic_inc_dec_x, _) (m, f, DEC, dec)

#define m4_ns(atomic_cmpxchg_x, _)(sz, _m, _a, _s, _f) \
  asm volatile ("pushq\t%q1;popfq;"					\
		ERI_STR (m4_ns(atomic_cmpxchg, __) (1, sz,		\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 3), %0))	\
		";pushfq;popq\t%q1"					\
		: "+m" (*_m), "+r" (*_f), "+a" (*_a) : "r" (_s)		\
		: "cc", "memory")

#define m4_ns(atomic_cmpxchg_x)(m, a, s, f) \
  do {									\
    typeof (m) _m = m;							\
    uint64_t *_a = a;							\
    typeof (*_m) _s = (typeof (*_m)) (s);				\
    uint64_t *_f = f;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_cmpxchg_x, _),		\
			     _a, _s, _f);				\
  } while (0)
