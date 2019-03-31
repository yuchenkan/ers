m4_include(`m4/util.m4')m4_dnl
m4_define(`m4_pub_start', `#ifndef ERS_PUBLIC_H
#define ERS_PUBLIC_H')m4_dnl
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
m4_define(`m4_pub_def', `#define ERS_$1')m4_dnl
m4_define(`m4_pub_impl', `_ERS_$1')m4_dnl
m4_define(`m4_pub_def_impl', `m4_dnl`'')m4_dnl
m4_define(`m4_pub_va_args', `##__VA_ARGS__')m4_dnl
m4_include(`public/public.h.in.m4')m4_dnl
