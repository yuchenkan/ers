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

#define m4_ns(atomic_common, _)(sz, _m, op, b) \
  asm volatile (ERI_STR (ERI_PASTE (m4_ns(atomic_, __), op) (1, sz,	\
							     %0))	\
		: "+m" (*_m) : : "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_common)(op, m, b) \
  do {									\
    typeof (m) _m = m;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_common, _), op, b);	\
  } while (0)

#define m4_ns(atomic_common2, _)(sz, _m, op, _v, b) \
  asm volatile (ERI_STR (ERI_PASTE (m4_ns(atomic_, __), op) (1, sz,	\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 1), %0))	\
		: "+m" (*_m) : "r" (_v) : "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_common2)(op, m, v, b) \
  do {									\
    typeof (m) _m = m;							\
    typeof (*_m) _v = (typeof (*_m)) (v);				\
    _eri_atomic_switch_size (_m, m4_ns(atomic_common2, _), op, _v, b);	\
  } while (0)

#define m4_ns(atomic_xcommon, _)(sz, _m, op, _r, b) \
  asm volatile (ERI_STR (ERI_PASTE (m4_ns(atomic_, __), op) (1, sz,	\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 0), %1))	\
		: "+r" (*_r), "+m" (*_m) : : "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_xcommon)(op, m, r, b) \
  do {									\
    typeof (m) _m = m;							\
    typeof (_m) _r = (typeof (_m)) (r);				\
    _eri_atomic_switch_size (_m, m4_ns(atomic_xcommon, _), op, _r, b);	\
  } while (0)

#define m4_ns(atomic_inc)(m, b)	\
  m4_ns(atomic_common) (inc, m, b)

#define m4_ns(atomic_dec)(m, b)	\
  m4_ns(atomic_common) (dec, m, b)

#define m4_ns(atomic_add)(m, v, b) \
  m4_ns(atomic_common2)(add, m, v, b)

#define m4_ns(atomic_sub)(m, v, b) \
  m4_ns(atomic_common2)(sub, m, v, b)

#define m4_ns(atomic_adc)(m, v, b) \
  m4_ns(atomic_common2)(adc, m, v, b)

#define m4_ns(atomic_sbb)(m, v, b) \
  m4_ns(atomic_common2)(sbb, m, v, b)

#define m4_ns(atomic_neg)(m, b) \
  m4_ns(atomic_common)(neg, m, b)

#define m4_ns(atomic_and)(m, v, b) \
  m4_ns(atomic_common2)(and, m, v, b)

#define m4_ns(atomic_or)(m, v, b) \
  m4_ns(atomic_common2)(or, m, v, b)

#define m4_ns(atomic_xor)(m, v, b) \
  m4_ns(atomic_common2)(xor, m, v, b)

#define m4_ns(atomic_not)(m, b) \
  m4_ns(atomic_common)(not, m, b)

#define m4_ns(atomic_btx, _)(sz, _m, op, _off, _r, b) \
  asm volatile (ERI_STR (ERI_PASTE (m4_ns(atomic_, __), op) (1, sz,	\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 2), %1))	\
		: "=@ccc" (_r), "+m" (*_m) : "r" (_off)			\
		: "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_btx)(op, m, off, b) \
  ({ typeof (m) _m = m;							\
     typeof (*_m) _off = off;						\
     uint8_t _r;							\
     _eri_atomic_switch_size1 (_m, m4_ns(atomic_btx, _), op,		\
			       _off, _r, b);	\
     _r; })

#define m4_ns(atomic_btc)(m, off, b) \
  m4_ns(atomic_btx) (btc, m, off, b)

#define m4_ns(atomic_btr)(m, off, b) \
  m4_ns(atomic_btx) (btr, m, off, b)

#define m4_ns(atomic_bts)(m, off, b) \
  m4_ns(atomic_btx) (bts, m, off, b)

#define m4_ns(atomic_xadd)(m, r, b) \
  m4_ns(atomic_xcommon) (xadd, m, r, b)

#define m4_ns(atomic_xchg)(m, r, b) \
  m4_ns(atomic_xcommon) (xchg, m, r, b)

#define m4_ns(atomic_cmpxchg, _)(sz, _m, _a, _r, b) \
  asm volatile (ERI_STR (m4_ns(atomic_cmpxchg, __) (1, sz,		\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 2), %0))	\
		: "+m" (*_m), "+a" (*_a) : "r" (_r)			\
		: "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_cmpxchg)(m, a, r, b) \
  ({ typeof (m) _m = m;							\
     typeof (_m) _a = (typeof (_m)) (a);				\
     typeof (*_m) _r = (typeof (*_m)) (r);				\
     _eri_atomic_switch_size (_m, m4_ns(atomic_cmpxchg, _), _a, _r, b);	\
     *_a; })

#define m4_ns(atomic_add_fetch)(m, v, b) \
  ({ typeof (*(m)) _v = (typeof (_v)) (v);				\
     typeof (_v) _o = _v;						\
     m4_ns(atomic_xadd) (m, &_v, b);					\
     (typeof (_v)) (_o + _v); })

#define m4_ns(atomic_inc_fetch)(m, b)	m4_ns(atomic_add_fetch) (m, 1, b)
#define m4_ns(atomic_dec_fetch)(m, b)	m4_ns(atomic_add_fetch) (m, -1, b)

#define m4_ns(atomic_fetch_inc)(m, b)	(m4_ns(atomic_inc_fetch) (m, b) - 1)
#define m4_ns(atomic_fetch_dec)(m, b)	(m4_ns(atomic_dec_fetch) (m, b) + 1)

#define m4_ns(atomic_bit_test_set)(m, off, b) \
  m4_ns(atomic_bts)(m, off, b) \

#define m4_ns(atomic_exchange)(m, v, b)	\
  ({ typeof (*(m)) _v = (typeof (_v)) (v);				\
     m4_ns(atomic_xchg) (m, &_v, b); _v; })

#define m4_ns(atomic_compare_exchange)(m, e, d, b) \
  ({ typeof (*(m)) _e = (typeof (_e)) (e);				\
     m4_ns(atomic_cmpxchg)(m, &_e, d, b); })

/* With rflags.  */
#define m4_ns(atomic_common_x, _)(sz, _m, op, _f, b) \
  asm volatile ("pushq\t%q0; popfq; "					\
		ERI_STR (ERI_PASTE (m4_ns(atomic_, __), op) (1, sz,	\
							     %1))	\
		"; pushfq; popq\t%q0"					\
		: "+r" (*_f), "+m" (*_m) : : "cc" ERI_PP_IF (b, m "memory"))

#define m4_ns(atomic_common_x)(op, m, f, b) \
  do {									\
    typeof (m) _m = m;							\
    uint64_t *_f = f;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_common_x, _),		\
			     op, _f, b);				\
  } while (0)

#define m4_ns(atomic_common2_x, _)(sz, _m, op, _v, _f, b) \
  asm volatile ("pushq\t%q0; popfq; "					\
		ERI_STR (ERI_PASTE (m4_ns(atomic_, __), op) (1, sz,	\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 2), %1))	\
		"; pushfq; popq\t%q0"					\
		: "+r" (*_f), "+m" (*_m) : "r" (_v)			\
		: "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_common2_x)(op, m, v, f, b) \
  do {									\
    typeof (m) _m = m;							\
    typeof (*_m) _v = v;						\
    uint64_t *_f = f;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_common2_x, _),		\
			     op, _v, _f, b);				\
  } while (0)

#define m4_ns(atomic_common2_x1)(op, m, v, f, b) \
  do {									\
    typeof (m) _m = m;							\
    typeof (*_m) _v = v;						\
    uint64_t *_f = f;							\
    _eri_atomic_switch_size1 (_m, m4_ns(atomic_common2_x, _),		\
			      op, _v, _f, b);				\
  } while (0)

#define m4_ns(atomic_inc_x)(m, f, b) \
  m4_ns(atomic_common_x) (inc, m, f, b)

#define m4_ns(atomic_dec_x)(m, f, b) \
  m4_ns(atomic_common_x) (dec, m, f, b)

#define m4_ns(atomic_add_x)(m, v, f, b) \
  m4_ns(atomic_common2_x) (add, m, v, f, b)

#define m4_ns(atomic_sub_x)(m, v, f, b) \
  m4_ns(atomic_common2_x) (sub, m, v, f, b)

#define m4_ns(atomic_adc_x)(m, v, f, b) \
  m4_ns(atomic_common2_x) (adc, m, v, f, b)

#define m4_ns(atomic_sbb_x)(m, v, f, b) \
  m4_ns(atomic_common2_x) (sbb, m, v, f, b)

#define m4_ns(atomic_neg_x)(m, f, b) \
  m4_ns(atomic_common_x) (neg, m, f, b)

#define m4_ns(atomic_and_x)(m, v, f, b) \
  m4_ns(atomic_common2_x) (and, m, v, f, b)

#define m4_ns(atomic_or_x)(m, v, f, b) \
  m4_ns(atomic_common2_x) (or, m, v, f, b)

#define m4_ns(atomic_xor_x)(m, v, f, b) \
  m4_ns(atomic_common2_x) (xor, m, v, f, b)

#define m4_ns(atomic_not_x)(m, f, b) \
  m4_ns(atomic_common_x) (not, m, f, b)

#define m4_ns(atomic_btc_x)(m, v, f, b) \
  m4_ns(atomic_common2_x1) (btc, m, v, f, b)

#define m4_ns(atomic_btr_x)(m, v, f, b) \
  m4_ns(atomic_common2_x1) (btr, m, v, f, b)

#define m4_ns(atomic_bts_x)(m, v, f, b) \
  m4_ns(atomic_common2_x1) (bts, m, v, f, b)

#define m4_ns(atomic_xadd_x, _)(sz, _m, _r, _f, b) \
  asm volatile ("pushq\t%q0; popfq; "					\
		ERI_STR (m4_ns(atomic_xadd, __) (1, sz,			\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 1), %2))	\
		"; pushfq; popq\t%q0"					\
		: "+r" (*_f), "+r" (*_r), "+m" (*_m)			\
		: : "cc" ERI_PP_IF (b, m "memory"))

#define m4_ns(atomic_xadd_x)(m, r, f, b) \
  do {									\
    typeof (m) _m = m;							\
    typeof (_m) _r = r;							\
    uint64_t *_f = f;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_xadd_x, _),		\
			     _r, _f, b);				\
  } while (0);

#define m4_ns(atomic_cmpxchg_x, _)(sz, _m, _a, _r, _f, b) \
  asm volatile ("pushq\t%q0; popfq; "					\
		ERI_STR (m4_ns(atomic_cmpxchg, __) (1, sz,		\
				%_ERI_ASM_TEMPLATE_SIZE (sz, 3), %1))	\
		";pushfq; popq\t%q0"					\
		: "+r" (*_f), "+m" (*_m), "+a" (*_a) : "r" (_r)		\
		: "cc" ERI_PP_IF (b, , "memory"))

#define m4_ns(atomic_cmpxchg_x)(m, a, r, f, b) \
  do {									\
    typeof (m) _m = m;							\
    uint64_t *_a = a;							\
    typeof (*_m) _r = (typeof (*_m)) (r);				\
    uint64_t *_f = f;							\
    _eri_atomic_switch_size (_m, m4_ns(atomic_cmpxchg_x, _),		\
			     _a, _r, _f, b);				\
  } while (0)

#endif
