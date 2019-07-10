m4_include(`m4/util.m4')m4_dnl
m4_pub_start
m4_pub_exp_nl

m4_ifdef(`m4_pub_no_exp', `',
`#define _ERS_EXPORT
#define _ERS_EXP_CONST(x)		m4_pub_eval(x)
#define _ERS_EXP_PASTE(x, y)		m4_pub_impl(m4_pub_paste) (x, y)
#define _ERS_EXP_REG(e, reg)		m4_pub_impl(m4_pub_pp_if) (e, %)%reg
#define _ERS_EXP_ATOMIC_SIZE(sz)	m4_pub_impl(m4_pub_paste) (m4_pub_impl(m4_pub_atomic_size), sz)
')m4_dnl
#include <public/impl.h>

m4_pub_def(INIT) m4_pub_lc
  m4_pub_impl(m4_pub_init)
m4_pub_exp_nl

m4_pub_def(SYSCALL)(esc) m4_pub_lc
  m4_pub_impl(m4_pub_syscall) (esc)
m4_pub_exp_nl

m4_pub_def(SYNC_ASYNC)(esc, inst) m4_pub_lc
  m4_pub_impl(m4_pub_sync_async) (esc, inst)
m4_pub_exp_nl

m4_define(`m4_atomic',
 `m4_pub_def(ATOMIC_$1)(esc, size, $2) m4_pub_lc
  m4_pub_impl(m4_expand(m4_pub_atomic_`'m4_lowcase($1))) (esc, size, m4_ifelse($#, 3, `$3', `$2'))')m4_dnl
m4_dnl
m4_atomic(COMMON_LOAD, `mem, op, ...', `mem, op, m4_pub_va_args')
m4_pub_exp_nl

m4_atomic(LOAD, `mem, reg')
m4_pub_exp_nl

m4_atomic(STORE, `imm_or_reg, mem')
m4_pub_exp_nl

m4_atomic(INC, mem)
m4_pub_exp_nl

m4_atomic(DEC, mem)
m4_pub_exp_nl

m4_atomic(XCHG, `reg, mem')
m4_pub_exp_nl

m4_atomic(CMPXCHG, `reg, mem')
m4_pub_exp_nl

m4_atomic(AND, `reg, mem')
m4_pub_exp_nl

m4_atomic(OR, `reg, mem')
m4_pub_exp_nl

m4_atomic(XOR, `reg, mem')
m4_pub_exp_nl

m4_atomic(XADD, `reg, mem')
m4_pub_exp_nl
m4_pub_exp_nl

m4_pub_def_impl(m4_pub_do_paste)(x, y) x##y
m4_pub_def_impl(m4_pub_paste)(x, y) m4_pub_impl(m4_pub_do_paste) (x, y)
m4_pub_def_impl(m4_pub_paste2)(x, y, z) m4_pub_impl(m4_pub_do_paste) (m4_pub_impl(m4_pub_paste) (x, y), z)
m4_pub_def_impl(m4_pub_pp_if, 0)(x)
m4_pub_def_impl(m4_pub_pp_if, 1)(x) x
m4_pub_def_impl(m4_pub_pp_if)(t, x) m4_pub_impl(m4_pub_paste) (m4_pub_impl(m4_pub_pp_if), t) (x)
m4_pub_def_impl(m4_pub_atomic_size, b)	_ERS_ATOMIC_SIZE_b
m4_pub_def_impl(m4_pub_atomic_size, w)	_ERS_ATOMIC_SIZE_w
m4_pub_def_impl(m4_pub_atomic_size, l)	_ERS_ATOMIC_SIZE_l
m4_pub_def_impl(m4_pub_atomic_size, q)	_ERS_ATOMIC_SIZE_q
m4_pub_def_impl(m4_pub_atomic_size)(sz) m4_pub_impl(m4_pub_paste) (m4_pub_impl(m4_pub_atomic_size), sz)
m4_pub_def_impl(m4_pub_init) _ERS_INIT
m4_pub_def_impl(m4_pub_syscall)(e) _ERS_SYSCALL (e) 
m4_pub_def_impl(m4_pub_sync_async)(e, i) _ERS_SYNC_ASYNC (e, i)
m4_define(`m4_atomic_impl',
 `m4_pub_def_impl(m4_pub_atomic_`'m4_lowcase($1))(e, s, $2) _ERS_ATOMIC_$1 (e, s, m4_ifelse($#, 3, `$3', `$2'))')m4_dnl
m4_atomic_impl(COMMON_LOAD, `m, o, ...', `m, o, m4_pub_va_args')
m4_atomic_impl(LOAD, `m, r')
m4_atomic_impl(STORE, `r, m')
m4_atomic_impl(INC, m)
m4_atomic_impl(DEC, m)
m4_atomic_impl(XCHG, `r, m')
m4_atomic_impl(CMPXCHG, `r, m')
m4_atomic_impl(AND, `r, m')
m4_atomic_impl(OR, `r, m')
m4_atomic_impl(XOR, `r, m')
m4_atomic_impl(XADD, `r, m')
m4_pub_exp_nl
m4_pub_end
