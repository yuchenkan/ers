m4_include(`m4/util.m4')m4_dnl
m4_define(`m4_pub_start', `#ifndef ERS_PUBLIC_PUBLIC_H
#define ERS_PUBLIC_PUBLIC_H')m4_dnl
m4_define(`m4_pub_end', `#endif')m4_dnl
m4_define(`m4_pub_no_exp', `')m4_dnl
m4_define(`m4_pub_exp_def', `m4_dnl')m4_dnl
m4_define(`m4_pub_exp_nl', `m4_dnl')m4_dnl
m4_define(`m4_pub_lc', `\')m4_dnl
m4_define(`m4_pub_init', `INIT')m4_dnl
m4_define(`m4_pub_syscall', `SYSCALL')m4_dnl
m4_define(`m4_pub_sync_async', `SYNC_ASYNC')m4_dnl
m4_define(`m4_pub_atomic_common_load', `ATOMIC_COMMON_LOAD')m4_dnl
m4_define(`m4_pub_atomic_load', `ATOMIC_LOAD')m4_dnl
m4_define(`m4_pub_atomic_store', `ATOMIC_STORE')m4_dnl
m4_define(`m4_pub_atomic_inc', `ATOMIC_INC')m4_dnl
m4_define(`m4_pub_atomic_dec', `ATOMIC_DEC')m4_dnl
m4_define(`m4_pub_atomic_xchg', `ATOMIC_XCHG')m4_dnl
m4_define(`m4_pub_atomic_cmpxchg', `ATOMIC_CMPXCHG')m4_dnl
m4_define(`m4_pub_atomic_add', `ATOMIC_ADD')m4_dnl
m4_define(`m4_pub_atomic_sub', `ATOMIC_SUB')m4_dnl
m4_define(`m4_pub_atomic_adc', `ATOMIC_ADC')m4_dnl
m4_define(`m4_pub_atomic_sbb', `ATOMIC_SBB')m4_dnl
m4_define(`m4_pub_atomic_neg', `ATOMIC_NEG')m4_dnl
m4_define(`m4_pub_atomic_and', `ATOMIC_AND')m4_dnl
m4_define(`m4_pub_atomic_or', `ATOMIC_OR')m4_dnl
m4_define(`m4_pub_atomic_xor', `ATOMIC_XOR')m4_dnl
m4_define(`m4_pub_atomic_not', `ATOMIC_NOT')m4_dnl
m4_define(`m4_pub_atomic_btc', `ATOMIC_BTC')m4_dnl
m4_define(`m4_pub_atomic_btr', `ATOMIC_BTR')m4_dnl
m4_define(`m4_pub_atomic_bts', `ATOMIC_BTS')m4_dnl
m4_define(`m4_pub_atomic_xadd', `ATOMIC_XADD')m4_dnl
m4_define(`m4_pub_def', `#define ERS_$1')m4_dnl
m4_define(`m4_pub_impl', `_ERS_$1')m4_dnl
m4_define(`m4_pub_def_impl', `m4_dnl`'')m4_dnl
m4_define(`m4_pub_va_args', `##__VA_ARGS__')m4_dnl
m4_include(`public/public.h.in.m4')m4_dnl
