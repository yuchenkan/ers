m4_include(`m4/util.m4')m4_dnl
m4_define(`m4_pub_start', `#ifndef ERS_H
#define ERS_H')m4_dnl
m4_define(`m4_pub_end', `#endif')m4_dnl
m4_define(`m4_pub_exp_nl', `')m4_dnl
m4_define(`m4_pub_lc', `\')m4_dnl
m4_define(`m4_pub_init', `0')m4_dnl
m4_define(`m4_pub_syscall', `1')m4_dnl
m4_define(`m4_pub_sync_async', `2')m4_dnl
m4_define(`m4_pub_atomic_common_load', `3')m4_dnl
m4_define(`m4_pub_atomic_load', `4')m4_dnl
m4_define(`m4_pub_atomic_store', `5')m4_dnl
m4_define(`m4_pub_atomic_inc', `6')m4_dnl
m4_define(`m4_pub_atomic_dec', `7')m4_dnl
m4_define(`m4_pub_atomic_xchg', `8')m4_dnl
m4_define(`m4_pub_atomic_cmpxchg', `9')m4_dnl
m4_define(`m4_pub_atomic_add', `10')m4_dnl
m4_define(`m4_pub_atomic_and', `11')m4_dnl
m4_define(`m4_pub_atomic_or', `12')m4_dnl
m4_define(`m4_pub_atomic_xor', `13')m4_dnl
m4_define(`m4_pub_atomic_xadd', `14')m4_dnl
m4_define(`m4_pub_do_paste', `a')m4_dnl
m4_define(`m4_pub_paste', `b')m4_dnl
m4_define(`m4_pub_paste2', `c')m4_dnl
m4_define(`m4_pub_pp_if', `d')m4_dnl
m4_define(`m4_pub_atomic_size', `e')m4_dnl
m4_define(`m4_pub_def', `#define ERS_$1')m4_dnl
m4_define(`m4_pub_impl', `_ERS$1`'m4_ifelse($#, 2, $2)')m4_dnl
m4_define(`m4_pub_def_impl', `#define _ERS$1`'m4_ifelse($#, 2, $2)')m4_dnl
m4_define(`m4_pub_eval', `m4_eval($1)')m4_dnl
m4_define(`m4_pub_va_args', `##__VA_ARGS__')m4_dnl
m4_include(`ers/public.h.in.m4')m4_dnl
