#undef _ERS_CFI_STARTPROC
#ifndef cfi_startproc
# define _ERS_CFI_STARTPROC .cfi_startproc
#else
# define _ERS_CFI_STARTPROC cfi_startproc
#endif

#undef _ERS_CFI_ENDPROC
#ifndef cfi_endproc
# define _ERS_CFI_ENDPROC .cfi_endproc
#else
# define _ERS_CFI_ENDPROC cfi_endproc
#endif

#undef _ERS_CFI_DEF_CFA
#ifndef cfi_def_cfa
# define _ERS_CFI_DEF_CFA(reg, off) .cfi_def_cfa reg, off
#else
# define _ERS_CFI_DEF_CFA(reg, off) cfi_def_cfa (reg, off)
#endif

#undef _ERS_CFI_DEF_CFA_REGISTER
#ifndef cfi_def_cfa_register
# define _ERS_CFI_DEF_CFA_REGISTER(reg) .cfi_def_cfa_register reg
#else
# define _ERS_CFI_DEF_CFA_REGISTER(reg) cfi_def_cfa_register (reg)
#endif

#undef _ERS_CFI_DEF_CFA_OFFSET
#ifndef cfi_def_cfa_offset
# define _ERS_CFI_DEF_CFA_OFFSET(off) .cfi_def_cfa_offset off
#else
# define _ERS_CFI_DEF_CFA_OFFSET(off) cfi_def_cfa_offset (off)
#endif

#undef _ERS_CFI_ADJUST_CFA_OFFSET
#ifndef cfi_adjust_cfa_offset
# define _ERS_CFI_ADJUST_CFA_OFFSET(off) .cfi_adjust_cfa_offset off
#else
# define _ERS_CFI_ADJUST_CFA_OFFSET(off) cfi_adjust_cfa_offset (off)
#endif

#undef _ERS_CFI_OFFSET
#ifndef cfi_offset
# define _ERS_CFI_OFFSET(reg, off) .cfi_offset reg, off
#else
# define _ERS_CFI_OFFSET(reg, off) cfi_offset (reg, off)
#endif

#undef _ERS_CFI_VAL_OFFSET
#ifndef cfi_val_offset
# define _ERS_CFI_VAL_OFFSET(reg, off) .cfi_val_offset reg, off
#else
# define _ERS_CFI_VAL_OFFSET(reg, off) cfi_val_offset (reg, off)
#endif

#undef _ERS_CFI_REL_OFFSET
#ifndef cfi_rel_offset
# define _ERS_CFI_REL_OFFSET(reg, off) .cfi_rel_offset reg, off
#else
# define _ERS_CFI_REL_OFFSET(reg, off) cfi_rel_offset (reg, off)
#endif

#undef _ERS_CFI_REGISTER
#ifndef cfi_register
# define _ERS_CFI_REGISTER(r1, r2) .cfi_register r1, r2
#else
# define _ERS_CFI_REGISTER(r1, r2) cfi_register (r1, r2)
#endif

#undef _ERS_CFI_RESTORE
#ifndef cfi_restore
# define _ERS_CFI_RESTORE(reg) .cfi_restore reg
#else
# define _ERS_CFI_RESTORE(reg) cfi_restore (reg)
#endif

#undef _ERS_CFI_SAME_VALUE
#ifndef cfi_same_value
# define _ERS_CFI_SAME_VALUE(reg) .cfi_same_value reg
#else
# define _ERS_CFI_SAME_VALUE(reg) cfi_same_value (reg)
#endif

#undef _ERS_CFI_UNDEFINED
#ifndef cfi_undefined
# define _ERS_CFI_UNDEFINED(reg) .cfi_undefined reg
#else
# define _ERS_CFI_UNDEFINED(reg) cfi_undefined (reg)
#endif

#undef _ERS_CFI_REMEMBER_STATE
#ifndef cfi_remember_state
# define _ERS_CFI_REMEMBER_STATE .cfi_remember_state
#else
# define _ERS_CFI_REMEMBER_STATE cfi_remember_state
#endif

#undef _ERS_CFI_RESTORE_STATE
#ifndef cfi_restore_state
# define _ERS_CFI_RESTORE_STATE .cfi_restore_state
#else
# define _ERS_CFI_RESTORE_STATE cfi_restore_state
#endif

#undef _ERS_CFI_ESCAPE
#ifndef cfi_escape
# define _ERS_CFI_ESCAPE(...) .cfi_escape __VA_ARGS__
#else
# define _ERS_CFI_ESCAPE(...) cfi_escape (__VA_ARGS__)
#endif

#ifndef ERS_RECORDER_PUB_H
#define ERS_RECORDER_PUB_H

#include "recorder-common.h"
#include "recorder-common-offsets.h"

#ifndef __ASSEMBLER__

#define ERS_SETUP_TLS_X(offset) \
  do {										\
    struct ers_recorder *__ers_recorder = ers_get_recorder ();			\
    if (__ers_recorder)								\
      __ers_recorder->setup_tls (offset);					\
  } while (0)

#define ERS_REPLACE_X(macro, ...) \
  do {										\
    struct ers_recorder *__ers_recorder = ers_get_recorder ();			\
    if (! (__ers_recorder && ers_##macro (__ers_recorder, ##__VA_ARGS__)))	\
      _##macro (__VA_ARGS__);							\
  } while (0)

#define ERS_REPLACE_EXP_X(macro, ...) \
  ({										\
    struct ers_recorder *__ers_recorder = ers_get_recorder ();			\
    typeof (_##macro(__VA_ARGS__)) __ers_res;					\
    __ers_recorder								\
    && ers_##macro (__ers_recorder, &__ers_res, ##__VA_ARGS__)			\
      ? __ers_res : _##macro (__VA_ARGS__);					\
  })

#define ers_internal_syscall0(rec, res, number, err) \
  ((rec)->syscall (number, 0, 0, 0, 0, 0, 0, (long *) (res)))
#define ers_internal_syscall1(rec, res, number, err, a1) \
  ((rec)->syscall (number, (long) (a1), 0, 0, 0, 0, 0, (long *) (res)))
#define ers_internal_syscall2(rec, res, number, err, a1, a2) \
  ((rec)->syscall (number, (long) (a1), (long) (a2), 0, 0, 0, 0, (long *) (res)))
#define ers_internal_syscall3(rec, res, number, err, a1, a2, a3) \
  ((rec)->syscall (number, (long) (a1), (long) (a2), (long) (a3), 0, 0, 0, (long *) (res)))
#define ers_internal_syscall4(rec, res, number, err, a1, a2, a3, a4) \
  ((rec)->syscall (number, (long) (a1), (long) (a2), (long) (a3), (long) (a4), 0, 0, (long *) (res)))
#define ers_internal_syscall5(rec, res, number, err, a1, a2, a3, a4, a5) \
  ((rec)->syscall (number, (long) (a1), (long) (a2), (long) (a3), (long) (a4), (long) (a5), 0, (long *) (res)))
#define ers_internal_syscall6(rec, res, number, err, a1, a2, a3, a4, a5, a6) \
  ((rec)->syscall (number, (long) (a1), (long) (a2), (long) (a3), (long) (a4), (long) (a5), (long) (a6), (long *) (res)))

#define ERS_ATOMIC_RELAXED 0
/* #define ERS_ATOMIC_CONSUME 1 */
#define ERS_ATOMIC_ACQUIRE 2
#define ERS_ATOMIC_RELEASE 3
#define ERS_ATOMIC_ACQ_REL 4
#define ERS_ATOMIC_SEQ_CST 5

#define ERS_ATOMIC_COMPARE_EXCHANGE_VAL(rec, res, mem, oldval, newval, succ_mo, fail_mo) \
  ({										\
    struct ers_recorder *__e10_rec = rec;					\
    typeof (mem) __e10_res = (typeof (__e10_res)) res;				\
    typeof (__e10_res) __e10_m = mem;						\
    typeof (*__e10_m) __e10_ov = (typeof (__e10_ov)) (oldval);			\
    typeof (*__e10_m) __e10_nv = (typeof (__e10_nv)) (newval);			\
    int __e10_smo = succ_mo, __e10_fmo = fail_mo;				\
    char __e10_rep = __e10_rec->atomic_lock ((void *) __e10_m);			\
    if (__e10_rep)								\
      {										\
	*__e10_res = *__e10_m;							\
        int __e10_mo = __e10_fmo;						\
	if (*__e10_m == __e10_ov)						\
	  {									\
	    *__e10_m = __e10_nv;						\
	    __e10_mo = __e10_smo;						\
	  }									\
	__e10_rec->atomic_unlock ((void *) __e10_m, __e10_mo);			\
      }										\
    __e10_rep;									\
  })

#define ERS_ATOMIC_COMPARE_EXCHANGE_BOOL(rec, res, mem, oldval, newval, succ_mo, fail_mo) \
  ({										\
    struct ers_recorder *__e20_rec = rec;					\
    typeof (res) __e20_res = res;						\
    typeof (mem) __e20_m = mem;							\
    typeof (*__e20_m) __e20_ov = (typeof (__e20_ov)) (oldval);			\
    typeof (*__e20_m) __e20_nv = (typeof (__e20_nv)) (newval);			\
    int __e20_smo = succ_mo, __e20_fmo = fail_mo;				\
    char __e20_rep = __e20_rec->atomic_lock ((void *) __e20_m);			\
    if (__e20_rep)								\
      {										\
	*__e20_res = *__e20_m == __e20_ov;					\
        int __e20_mo = __e20_fmo;						\
	if (*__e20_res)								\
	  {									\
	    *__e20_m = __e20_nv;						\
	    __e20_mo = __e20_smo;						\
	  }									\
	__e20_rec->atomic_unlock ((void *) __e20_m, __e20_mo);			\
      }										\
    __e20_rep;									\
  })

#define _ERS_ATOMIC_FETCH_OP(rec, res, mem, value, mo, op) \
  ({										\
    struct ers_recorder *__e30_rec = rec;					\
    typeof (mem) __e30_res = (typeof (__e30_res)) res;				\
    typeof (__e30_res) __e30_m = mem;						\
    typeof (*__e30_m) __e30_v = (typeof (__e30_v)) (value);			\
    int __e30_mo = mo;								\
    char __e30_rep = __e30_rec->atomic_lock ((void *) __e30_m);			\
    if (__e30_rep)								\
      {										\
	if (__e30_res) *__e30_res = *__e30_m;					\
	*__e30_m = op (*__e30_m, __e30_v);					\
	__e30_rec->atomic_unlock ((void *) __e30_m, __e30_mo);			\
      }										\
    __e30_rep;									\
  })

#define _ERS_ATOMIC_OP_CHANGE(oldval, newval) (newval)
#define _ERS_ATOMIC_OP_ADD(oldval, newval) ((oldval) + (newval))
#define _ERS_ATOMIC_OP_AND(oldval, newval) ((oldval) & (newval))
#define _ERS_ATOMIC_OP_OR(oldval, newval) ((oldval) | (newval))
#define _ERS_ATOMIC_OP_XOR(oldval, newval) ((oldval) ^ (newval))

#define ERS_ATOMIC_EXCHANGE(rec, res, mem, value, mo) \
  _ERS_ATOMIC_FETCH_OP (rec, res, mem, value, mo, _ERS_ATOMIC_OP_CHANGE)
#define ERS_ATOMIC_FETCH_ADD(rec, res, mem, value, mo) \
  _ERS_ATOMIC_FETCH_OP (rec, res, mem, value, mo, _ERS_ATOMIC_OP_ADD)
#define ERS_ATOMIC_FETCH_AND(rec, res, mem, value, mo) \
  _ERS_ATOMIC_FETCH_OP (rec, res, mem, value, mo, _ERS_ATOMIC_OP_AND)
#define ERS_ATOMIC_FETCH_OR(rec, res, mem, value, mo) \
  _ERS_ATOMIC_FETCH_OP (rec, res, mem, value, mo, _ERS_ATOMIC_OP_OR)
#define ERS_ATOMIC_FETCH_XOR(rec, res, mem, value, mo) \
  _ERS_ATOMIC_FETCH_OP (rec, res, mem, value, mo, _ERS_ATOMIC_OP_XOR)

#define _ERS_ATOMIC_OP_SUB_IF_POS(oldval, newval) \
  ({										\
    typeof (oldval) __e40_ov = oldval;						\
    typeof (newval) __e40_nv = newval;						\
    __e40_ov > __e40_nv								\
      ? __e40_ov - __e40_nv : __e40_ov;						\
  })

#define ERS_ATOMIC_DECREMENT_IF_POSITIVE(rec, res, mem) \
  _ERS_ATOMIC_FETCH_OP (rec, res, mem, 1, ERS_ATOMIC_SEQ_CST, _ERS_ATOMIC_OP_SUB_IF_POS)

#define ERS_ATOMIC_LOAD(rec, res, mem, mo) \
  ({										\
    struct ers_recorder *__e50_rec = rec;					\
    typeof (res) __e50_res = res;						\
    typeof (mem) __e50_m = mem;							\
    int __e50_mo = mo;								\
    char __e50_rep = __e50_rec->atomic_lock ((void *) __e50_m);			\
    if (__e50_rep)								\
      {										\
	*__e50_res = *__e50_m;							\
	__e50_rec->atomic_unlock ((void *) __e50_m, __e50_mo);			\
      }										\
    __e50_rep;									\
  })

#define ERS_ATOMIC_STORE(rec, mem, value, mo) \
  ({										\
    struct ers_recorder *__e60_rec = rec;					\
    typeof (mem) __e60_m = mem;							\
    typeof (*__e60_m) __e60_v = (typeof (__e60_v)) (value);			\
    int __e60_mo = mo;								\
    char __e60_rep = __e60_rec->atomic_lock ((void *) __e60_m);			\
    if (__e60_rep)								\
      {										\
	*__e60_m = __e60_v;							\
	__e60_rec->atomic_unlock ((void *) __e60_m, __e60_mo);			\
      }										\
    __e60_rep;									\
  })

#define _ERS_ATOMIC_OP_MAX(oldval, newval) \
  ({										\
    typeof (oldval) __e70_ov = oldval;						\
    typeof (newval) __e70_nv = newval;						\
    __e70_ov > __e70_nv ? __e70_ov : __e70_nv;					\
  })
#define _ERS_ATOMIC_OP_MIN(oldval, newval) \
  ({										\
    typeof (oldval) __e80_ov = oldval;						\
    typeof (newval) __e80_nv = newval;						\
    __e80_ov < __e80_nv ? __e80_ov : __e80_nv;					\
  })

#define ERS_ATOMIC_MAX(rec, mem, value) \
  _ERS_ATOMIC_FETCH_OP (rec, 0, mem, value, ERS_ATOMIC_SEQ_CST, _ERS_ATOMIC_OP_MAX)
#define ERS_ATOMIC_MIN(rec, mem, value) \
  _ERS_ATOMIC_FETCH_OP (rec, 0, mem, value, ERS_ATOMIC_SEQ_CST, _ERS_ATOMIC_OP_MIN)

#define ERS_ATOMIC_BARRIER(rec, mo) (rec)->atomic_barrier (mo)

#define ERS_ATOMIC_COMPARE_EXCHANGE(rec, res, mem, expected, desired, succ_mo, fail_mo) \
  ({										\
    typeof (expected) __e90_e = expected;					\
    typeof (*__e90_e) __e90_ev = *__e90_e;					\
    char __e90_rep = ERS_ATOMIC_COMPARE_EXCHANGE_VAL (				\
			rec, __e90_e, mem, __e90_ev, desired,			\
			succ_mo, fail_mo);					\
    if (__e90_rep) *(res) = *__e90_e == __e90_ev;				\
    __e90_rep;									\
  })

#define ers_atomic_compare_and_exchange_val_acq(rec, res, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, res, mem, oldval, newval,		\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_compare_and_exchange_val_acq(rec, res, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, res, mem, oldval, newval,		\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_compare_and_exchange_val_rel(rec, res, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, res, mem, oldval, newval,		\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_compare_and_exchange_val_rel(rec, res, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, res, mem, oldval, newval,		\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_compare_and_exchange_bool_acq(rec, res, mem, newval, oldval) \
  /* As __sync_bool_compare_and_swap */						\
  ({										\
    typeof (res) __ea0_res = res;						\
    char __ea0_rep = ERS_ATOMIC_COMPARE_EXCHANGE_BOOL (				\
			rec, __ea0_res, mem, oldval, newval,			\
			ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST);		\
    if (__ea0_rep) *__ea0_res = ! *__ea0_res;					\
    __ea0_rep;									\
  })
#define ers_catomic_compare_and_exchange_bool_acq(rec, res, mem, newval, oldval) \
  ers_atomic_compare_and_exchange_bool_acq (rec, res, mem, newval, oldval)
#define ers_atomic_exchange_acq(rec, res, mem, value) \
  ERS_ATOMIC_EXCHANGE (rec, res, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_rel(rec, res, mem, value) \
  ERS_ATOMIC_EXCHANGE (rec, res, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add_acq(rec, res, mem, value) \
  ERS_ATOMIC_FETCH_ADD (rec, res, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add_rel(rec, res, mem, value) \
  ERS_ATOMIC_FETCH_ADD (rec, res, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add(rec, res, mem, value) \
  ERS_ATOMIC_FETCH_ADD (rec, res, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_exchange_and_add(rec, res, mem, value) \
  ERS_ATOMIC_FETCH_ADD (rec, res, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_max(rec, mem, value) \
  ERS_ATOMIC_MAX (rec, mem, value)
#define ers_catomic_max(rec, mem, value) \
  ERS_ATOMIC_MAX (rec, mem, value)
#define ers_atomic_min(rec, res, mem, value) \
  ERS_ATOMIC_MIN (rec, res, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_add(rec, mem, value) \
  ERS_ATOMIC_FETCH_ADD (rec, 0, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_add(rec, mem, value) \
  ERS_ATOMIC_FETCH_ADD (rec, 0, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_increment(rec, mem) \
  ERS_ATOMIC_FETCH_ADD (rec, 0, mem, 1, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_increment(rec, mem) \
  ERS_ATOMIC_FETCH_ADD (rec, 0, mem, 1, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_increment_val(rec, res, mem) \
  ({										\
    typeof (res) __eb0_res = res;						\
    char __eb0_rep = ERS_ATOMIC_FETCH_ADD (					\
			rec, __eb0_res, mem, 1, ERS_ATOMIC_SEQ_CST);		\
    if (__eb0_rep) ++*__eb0_res;						\
    __eb0_rep;									\
  })
#define ers_catomic_increment_val(rec, res, mem) \
  ers_atomic_increment_val (rec, res, mem)
#define ers_atomic_increment_and_test(rec, res, mem) \
  ({										\
    typeof (*mem) __ec0_res;							\
    char __ec0_rep = ers_atomic_increment_val (rec, &__ec0_res, mem);		\
    if (__ec0_rep) *(res) = __ec0_res == 0;					\
    __ec0_rep;									\
  })
#define ers_atomic_decrement(rec, mem) \
  ERS_ATOMIC_FETCH_ADD (rec, 0, mem, -1, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_decrement(rec, mem) \
  ERS_ATOMIC_FETCH_ADD (rec, 0, mem, -1, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_decrement_val(rec, res, mem) \
  ({										\
    typeof (res) __ed0_res = res;						\
    char __ed0_rep = ERS_ATOMIC_FETCH_ADD (					\
			rec, __ed0_res, mem, -1, ERS_ATOMIC_SEQ_CST);		\
    if (__ed0_rep) --*__ed0_res;						\
    __ed0_rep;									\
  })
#define ers_catomic_decrement_val(rec, res, mem) \
  ers_atomic_decrement_val (rec, res, mem)
#define ers_atomic_decrement_and_test(rec, res, mem) \
  ({										\
    typeof (*(mem)) __ee0_res;							\
    char __ee0_rep = ers_atomic_decrement_val (rec, &__ee0_res, mem);		\
    if (__ee0_rep) *(res) = __ee0_res == 0;					\
    __ee0_rep;									\
  })
#define ers_atomic_decrement_if_positive(rec, res, mem) \
  ERS_ATOMIC_DECREMENT_IF_POSITIVE (rec, res, mem)
#define ers_atomic_add_negative(rec, res, mem, value) \
  ({										\
    typeof (value) __ef0_v = value;						\
    typeof (*(mem)) __ef0_res;							\
    char __ef0_rep = ERS_ATOMIC_FETCH_ADD (					\
			rec, &__ef0_res, mem, __ef0_v, ERS_ATOMIC_SEQ_CST);	\
    if (__ef0_rep) *(res) = __ef0_res < -__ef0_v;				\
    __ef0_resp;									\
  })
#define ers_atomic_add_zero(rec, res, mem, value) \
  ({										\
    typeof (value) __eg0_v = value;						\
    typeof (*(mem)) __eg0_res;							\
    char __eg0_rep = ERS_ATOMIC_FETCH_ADD (					\
			rec, &__eg0_res, mem, __eg0_v, ERS_ATOMIC_SEQ_CST);	\
    if (__eg0_rep) *(res) = __eg0_res == -__eg0_v;				\
    __eg0_rep;									\
  })
#define ers_atomic_bit_set(rec, mem, bit) \
  ERS_ATOMIC_FETCH_OR (rec, 0, mem, ((typeof (*(mem))) 1 << (bit)), ERS_ATOMIC_SEQ_CST)
#define ers_atomic_bit_test_set(rec, res, mem, bit) \
  ({										\
    typeof (*(mem)) __eh0_mask = ((typeof (*(mem))) 1 << (bit));		\
    typeof (*(mem)) __eh0_res;							\
    char __eh0_rep = ERS_ATOMIC_FETCH_OR (					\
			rec, &__eh0_res, mem, __eh0_mask, ERS_ATOMIC_SEQ_CST);	\
    if (__eh0_rep) *(res) = __eh0_res & __eh0_mask;				\
    __eh0_rep;									\
  })
#define ers_atomic_and(rec, mem, mask) \
  ERS_ATOMIC_FETCH_AND (rec, 0, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_and(rec, mem, mask) \
  ERS_ATOMIC_FETCH_AND (rec, 0, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_and_val(rec, res, mem, mask) \
  ERS_ATOMIC_FETCH_AND (rec, res, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_or(rec, mem, mask) \
  ERS_ATOMIC_FETCH_OR (rec, 0, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_or(rec, mem, mask) \
  ERS_ATOMIC_FETCH_OR (rec, 0, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_or_val(rec, th, mem, mask) \
  ERS_ATOMIC_FETCH_OR (rec, th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_full_barrier(rec) ERS_ATOMIC_BARRIER (rec, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_read_barrier(rec) ERS_ATOMIC_BARRIER (rec, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_write_barrier(rec) ERS_ATOMIC_BARRIER (rec, ERS_ATOMIC_RELEASE)
#define ers_atomic_forced_read(rec, res, x) \
  ERS_ATOMIC_LOAD (rec, res, &(x), ERS_ATOMIC_RELAXED)
#define ers_atomic_thread_fence_acquire(rec) \
  ERS_ATOMIC_BARRIER (rec, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_thread_fence_release(rec) \
  ERS_ATOMIC_BARRIER (rec, ERS_ATOMIC_RELEASE)
#define ers_atomic_thread_fence_seq_cst(rec) \
  ERS_ATOMIC_BARRIER (rec, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_load_relaxed(rec, res, mem) \
  ERS_ATOMIC_LOAD (rec, res, mem, ERS_ATOMIC_RELAXED)
#define ers_atomic_load_acquire(rec, res, mem) \
  ERS_ATOMIC_LOAD (rec, res, mem, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_store_relaxed(rec, mem, val) \
  ERS_ATOMIC_STORE (rec, mem, val, ERS_ATOMIC_RELAXED)
#define ers_atomic_store_release(rec, mem, val) \
  ERS_ATOMIC_STORE (rec, mem, val, ERS_ATOMIC_RELEASE)
#define ers_atomic_compare_exchange_weak_relaxed(rec, res, mem, expected, desired) \
  ERS_ATOMIC_COMPARE_EXCHANGE (rec, res, mem, expected, desired,		\
			       ERS_ATOMIC_ACQUIRE, ERS_ATOMIC_RELAXED)
#define ers_atomic_compare_exchange_weak_acquire(rec, res, mem, expected, desired) \
  ERS_ATOMIC_COMPARE_EXCHANGE (rec, res, mem, expected, desired,		\
			       ERS_ATOMIC_ACQUIRE, ERS_ATOMIC_RELAXED)
#define ers_atomic_compare_exchange_weak_release(rec, res, mem, expected, desired) \
  ERS_ATOMIC_COMPARE_EXCHANGE (rec, res, mem, expected, desired,		\
			       ERS_ATOMIC_RELEASE, ERS_ATOMIC_RELAXED)
#define ers_atomic_exchange_relaxed(rec, res, mem, desired) \
  ERS_ATOMIC_EXCHANGE (rec, res, mem, desired, ERS_ATOMIC_RELAXED)
#define ers_atomic_exchange_acquire(rec, res, mem, desired) \
  ERS_ATOMIC_EXCHANGE (rec, res, mem, desired, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_exchange_release(rec, res, mem, desired) \
  ERS_ATOMIC_EXCHANGE (rec, res, mem, desired, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_add_relaxed(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (rec, res, mem, operand, ERS_ATOMIC_RELAXED)
#define ers_atomic_fetch_add_acquire(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (rec, res, mem, operand, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_fetch_add_release(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (rec, res, mem, operand, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_add_acq_rel(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (rec, res, mem, operand, ERS_ATOMIC_ACQ_REL)
#define ers_atomic_fetch_and_relaxed(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_AND (rec, res, mem, operand, ERS_ATOMIC_RELAXED)
#define ers_atomic_fetch_and_acquire(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_AND (rec, res, mem, operand, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_fetch_and_release(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_AND (rec, res, mem, operand, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_or_relaxed(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_OR (rec, res, mem, operand, ERS_ATOMIC_RELAXED)
#define ers_atomic_fetch_or_acquire(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_OR (rec, res, mem, operand, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_fetch_or_release(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_OR (rec, res, mem, operand, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_xor_release(rec, res, mem, operand) \
  ERS_ATOMIC_FETCH_XOR (rec, res, mem, operand, ERS_ATOMIC_RELEASE)

#define ers_THREAD_ATOMIC_CMPXCHG_VAL(rec, res, descr, member, new, old) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, res, &(descr)->member, new, old,	\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_THREAD_ATOMIC_AND(rec, descr, member, val) \
  ERS_ATOMIC_FETCH_AND (rec, 0, &(descr)->member, val, ERS_ATOMIC_SEQ_CST)
#define ers_THREAD_ATOMIC_BIT_SET(rec, descr, member, bit) \
  ERS_ATOMIC_FETCH_OR (rec, 0, &(descr)->member,			\
		       ((typeof ((descr)->member)) 1 << (bit)), ERS_ATOMIC_SEQ_CST)

#endif

#define _ERS_ASM_START_FRAME(l1, l2) \
l1:					\
  call	l2##f;				\
l2:					\
  _ERS_CFI_STARTPROC;			\
  _ERS_CFI_ESCAPE (0x16 /* DW_CFA_val_expression */,	\
		   16 /* rip */, 7,			\
		   0x09 /* DW_OP_const1s */, -8,	\
		   0x22 /* DW_OP_plus */,		\
		   0x06 /* DW_OP_deref */,		\
		   0x09 /* DW_OP_const1s */,		\
		   l1##b-l2##b, 0x22 /* DW_OP_plus */);

#define _ERS_ASM_END_FRAME(esc, v) \
  leaq	v+8(esc%rsp), esc%rsp;		\
  _ERS_CFI_ENDPROC;

#define _ERS_ASM_PUSH_FRAME(esc, l) \
  call	l##f;				\
l:					\
  _ERS_CFI_REMEMBER_STATE;		\
  _ERS_CFI_DEF_CFA (esc%rsp, 8);	\
  _ERS_CFI_SAME_VALUE (esc%rax);	\
  _ERS_CFI_SAME_VALUE (esc%rdx);	\
  _ERS_CFI_SAME_VALUE (esc%rcx);	\
  _ERS_CFI_SAME_VALUE (esc%rbx);	\
  _ERS_CFI_SAME_VALUE (esc%rsi);	\
  _ERS_CFI_SAME_VALUE (esc%rdi);	\
  _ERS_CFI_SAME_VALUE (esc%rbp);	\
  _ERS_CFI_VAL_OFFSET (esc%rsp, 0);	\
  _ERS_CFI_SAME_VALUE (esc%r8);		\
  _ERS_CFI_SAME_VALUE (esc%r9);		\
  _ERS_CFI_SAME_VALUE (esc%r10);	\
  _ERS_CFI_SAME_VALUE (esc%r11);	\
  _ERS_CFI_SAME_VALUE (esc%r12);	\
  _ERS_CFI_SAME_VALUE (esc%r13);	\
  _ERS_CFI_SAME_VALUE (esc%r14);	\
  _ERS_CFI_SAME_VALUE (esc%r15);	\
  _ERS_CFI_OFFSET (esc%rip, -8);

#define _ERS_ASM_POP_FRAME(esc, v)	\
  leaq	v+8(esc%rsp), esc%rsp;		\
  _ERS_CFI_RESTORE_STATE;

#define _ERS_ASM_SYSCALL(esc, outside) \
  _ERS_PP_IF (outside, _ERS_ASM_START_FRAME (91, 92))				\
  _ERS_PP_IF (_ERS_PP_NOT (outside), _ERS_ASM_PUSH_FRAME (esc, 91))		\
  pushq	esc%rax;		/* nr */					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);						\
  _ERS_CFI_REL_OFFSET (esc%rax, 0);						\
										\
  pushq	esc%rbx;								\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);						\
  _ERS_CFI_REL_OFFSET (esc%rbx, 0);						\
  pushq	esc%rbp;								\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);						\
  _ERS_CFI_REL_OFFSET (esc%rbp, 0);						\
  pushq	esc%rdi;		/* a1 */					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);						\
  _ERS_CFI_REL_OFFSET (esc%rdi, 0);						\
  pushq	esc%rsi;		/* a2 */					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);						\
  _ERS_CFI_REL_OFFSET (esc%rsi, 0);						\
  pushq	esc%rdx;		/* a3 */					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);						\
  _ERS_CFI_REL_OFFSET (esc%rdx, 0);						\
  pushq	esc%r10;		/* a4 */					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);						\
  _ERS_CFI_REL_OFFSET (esc%r10, 0);						\
  pushq	esc%r8;			/* a5 */					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);						\
  _ERS_CFI_REL_OFFSET (esc%r8, 0);						\
  pushq	esc%r9;			/* a6 */					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);						\
  _ERS_CFI_REL_OFFSET (esc%r9, 0);						\
										\
  cmpl	$56, esc%eax;								\
  jne	93f;			/* not clone */					\
  subq	$64, esc%rsi;								\
  movq	esc%rbx, 48(esc%rsi);							\
  movq	esc%rbp, 40(esc%rsi);							\
  movq	esc%rdi, 32(esc%rsi);							\
  movq	esc%rdx, 24(esc%rsi);							\
  movq	esc%r10, 16(esc%rsi);							\
  movq	esc%r8, 8(esc%rsi);							\
  movq	esc%r9, (esc%rsi);							\
93:										\
  pushq	esc%rsi;		/* rsi may change */				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);						\
										\
  movq	esc%rsp, esc%rbp;							\
  _ERS_CFI_DEF_CFA_REGISTER (esc%rbp);						\
  subq	$8, esc%rsp;								\
  andq	$-16, esc%rsp;		/* align stack */				\
  movq  esc%rbp, (esc%rsp);							\
										\
  call	ers_get_recorder@PLT;							\
  testq	esc%rax, esc%rax;	/* ers_recorder */				\
  jz	95f;			/* no ers_recorder, real syscall */		\
										\
  movq	esc%rax, esc%rbx;							\
  subq	$16, esc%rsp;		/* alignment, res */				\
  pushq	esc%rsp;		/* &res */					\
  movq	8(esc%rbp), esc%rax;							\
  pushq	esc%rax;		/* a6 */					\
  movq	16(esc%rbp), esc%r9;	/* a5 */					\
  movq	24(esc%rbp), esc%r8;	/* a4 */					\
  movq	32(esc%rbp), esc%rcx;	/* a3 */					\
  movq	(esc%rbp), esc%rdx;	/* a2 */					\
  movq	48(esc%rbp), esc%rsi;	/* a1 */			       		\
  movl	72(esc%rbp), esc%edi;	/* nr */					\
  call	*_ERS_REC_SYSCALL(esc%rbx);	/* call ers_recorder->syscall */	\
										\
  _ERS_CFI_UNDEFINED (esc%rip);							\
  cmpb	$2, esc%al;								\
  jne	94f;			/* not child */					\
										\
  popq	esc%r9;			/* child, restore registers */			\
  popq	esc%r8;									\
  popq	esc%r10;								\
  popq	esc%rdx;								\
  popq	esc%rdi;								\
  popq	esc%rbp;								\
  popq	esc%rbx;								\
  addq	$8, esc%rsp;								\
  movq	esc%rsp, esc%rsi;							\
  xorq	esc%rax, esc%rax;							\
  jmp	97f;			/* child, leave */				\
  _ERS_CFI_RESTORE (esc%rip);							\
										\
94:										\
  movb	esc%al, esc%bl;								\
  movq	16(esc%rsp), esc%rax;							\
  addq	$32, esc%rsp;								\
  testb	esc%bl, esc%bl;								\
										\
95:										\
  popq  esc%rsp;								\
  _ERS_CFI_DEF_CFA_REGISTER (esc%rsp);						\
  leaq	8(esc%rsp), esc%rsp;	/* rsi */					\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);						\
  popq	esc%r9;									\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);						\
  _ERS_CFI_RESTORE (esc%r9);							\
  popq	esc%r8;									\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);						\
  _ERS_CFI_RESTORE (esc%r8);							\
  popq	esc%r10;								\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);						\
  _ERS_CFI_RESTORE (esc%r10);							\
  popq	esc%rdx;								\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);						\
  _ERS_CFI_RESTORE (esc%rdx);							\
  popq	esc%rsi;								\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);						\
  _ERS_CFI_RESTORE (esc%rsi);							\
  popq	esc%rdi;								\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);						\
  _ERS_CFI_RESTORE (esc%rdi);							\
  popq	esc%rbp;								\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);						\
  _ERS_CFI_RESTORE (esc%rbp);							\
  popq	esc%rbx;								\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);						\
  _ERS_CFI_RESTORE (esc%rbx);							\
  jnz	96f;			/* replaced, leave */				\
										\
  popq	esc%rax;								\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);						\
  _ERS_CFI_RESTORE (esc%rax);							\
  leaq	8(esc%rsp), esc%rsp;							\
  _ERS_CFI_UNDEFINED (esc%rip);							\
  syscall;									\
  _ERS_CFI_UNDEFINED (esc%rax);							\
  jmp	97f;									\
										\
96:										\
  _ERS_CFI_RESTORE (esc%rax);							\
  addq	$8, esc%rsp;								\
  _ERS_CFI_UNDEFINED (esc%rax);							\
  _ERS_PP_IF (outside, _ERS_ASM_END_FRAME (esc, 0))				\
  _ERS_PP_IF (_ERS_PP_NOT (outside), _ERS_ASM_POP_FRAME (esc, 0))		\
97:

#define ERS_ASM_SYSCALL _ERS_ASM_SYSCALL (ERS_NONE, 0)
#define ERS_ASM_CLONE _ERS_ASM_SYSCALL (ERS_NONE, 1)

#define _ERS_ASM_PUSH_SCRATCH_REGS(esc) \
  pushq	esc%rax;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%rax, 0);		\
  pushq	esc%rdi;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%rdi, 0);		\
  pushq	esc%rsi;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%rsi, 0);		\
  pushq	esc%rdx;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%rdx, 0);		\
  pushq	esc%rcx;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%rcx, 0);		\
  pushq	esc%r8;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%r8, 0);		\
  pushq	esc%r9;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%r9, 0);		\
  pushq	esc%r10;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%r10, 0);		\
  pushq	esc%r11;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%r11, 0);

# define _ERS_ASM_POP_SCRATCH_REGS(esc) \
  popq	esc%r11;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%r11);			\
  popq	esc%r10;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%r10);			\
  popq	esc%r9;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%r9);			\
  popq	esc%r8;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%r8);			\
  popq	esc%rcx;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rcx);			\
  popq	esc%rdx;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rdx);			\
  popq	esc%rsi;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rsi);			\
  popq	esc%rdi;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rdi);			\
  popq	esc%rax;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rax);

/* %r13 is the address to be locked.
   All the registers are restored.
   Instructions followed LOCK_2 are executed when there is no
   interception. Otherwise the execution jumps to 92f.  */
#define _ERS_ASM_LOCK_1(esc) \
  pushfq;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  pushq	esc%rbx;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%rbx, 0);		\
  pushq	esc%rbp;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%rbp, 0);		\
  _ERS_ASM_PUSH_SCRATCH_REGS (esc)		\
  movq	esc%rsp, esc%rbp;			\
  _ERS_CFI_DEF_CFA_REGISTER (esc%rbp);		\
  subq	$8, esc%rsp;				\
  andq	$-16, esc%rsp;				\
  movq	esc%rbp, (esc%rsp);			\
  call	ers_get_recorder@PLT;			\
  testq	esc%rax, esc%rax;			\
  _ERS_CFI_REMEMBER_STATE;			\
  jz	91f;					\
						\
  movq	esc%r13, esc%rdi;			\
  movq	esc%rax, esc%rbx;			\
  call	*_ERS_REC_ATOMIC_LOCK(esc%rbx);		\
  testb	esc%al, esc%al;				\
  jz	91f;					\
  popq	esc%rsp;				\
  _ERS_CFI_DEF_CFA_REGISTER (esc%rsp);		\
  _ERS_ASM_POP_SCRATCH_REGS (esc)		\
  popq	esc%rbp;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rbp);			\
  popq	esc%rbx;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rbx);			\
  popfq;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);

#define _ERS_ASM_LOCK_2(esc) \
  pushfq;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  pushq	esc%rbx;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%rbx, 0);		\
  pushq	esc%rbp;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%rbp, 0);		\
  _ERS_ASM_PUSH_SCRATCH_REGS (esc)		\
  _ERS_CFI_DEF_CFA_REGISTER (esc%rbp);		\
  movq	esc%rsp, esc%rbp;			\
  subq	$8, esc%rsp;				\
  andq	$-16, esc%rsp;				\
  movq	esc%rbp, (esc%rsp);			\
  call	ers_get_recorder@PLT;			\
  movq	esc%r13, esc%rdi;			\
  movl	$5, esc%esi;				\
  movq	esc%rax, esc%rbx;			\
  call	*_ERS_REC_ATOMIC_UNLOCK(esc%rbx);	\
  popq	esc%rsp;				\
  _ERS_CFI_DEF_CFA_REGISTER (esc%rsp);		\
  _ERS_ASM_POP_SCRATCH_REGS (esc)		\
  popq	esc%rbp;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rbp);			\
  popq	esc%rbx;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rbx);			\
  popfq;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  jmp	92f;					\
91:						\
  _ERS_CFI_RESTORE_STATE;			\
  popq	esc%rsp;				\
  _ERS_CFI_DEF_CFA_REGISTER (esc%rsp);		\
  _ERS_ASM_POP_SCRATCH_REGS (esc)		\
  popq	esc%rbp;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rbp);			\
  popq	esc%rbx;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%rbx);			\
  popfq;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);

/* lock; cmpl %r12d, (%r13) */
#define __ERS_ASM_CMPL(esc, ...) \
  _ERS_ASM_LOCK_1 (esc)	 			\
  cmpl	esc%r12d, (esc%r13);			\
  _ERS_ASM_LOCK_2 (esc)				\
  cmpl	esc%r12d, (esc%r13);			\
92:

/* lock; movl %r12d, (%r13) */
#define __ERS_ASM_MOVL_SV(esc, ...) \
  _ERS_ASM_LOCK_1 (esc)				\
  movl	esc%r12d, (esc%r13);			\
  _ERS_ASM_LOCK_2 (esc)				\
  movl	esc%r12d, (esc%r13);			\
92:

/* lock; movl (%r13), %r12d */
#define __ERS_ASM_MOVL_LD(esc, ...) \
  _ERS_ASM_LOCK_1 (esc)				\
  movl	(esc%r13), esc%r12d;			\
  _ERS_ASM_LOCK_2 (esc)				\
  movl	(esc%r13), esc%r12d;			\
92:

/* lock; decl (%r13) */
#define __ERS_ASM_DECL(esc, lock) \
  _ERS_ASM_LOCK_1 (esc)				\
  decl	(esc%r13);				\
  _ERS_ASM_LOCK_2 (esc)				\
  lock;	decl	(esc%r13);			\
92:

/* xchgl %r12d, (%r13) */
#define __ERS_ASM_XCHGL(esc, ...) \
  _ERS_ASM_LOCK_1 (esc)				\
  xchgl	esc%r12d, (esc%r13);			\
  _ERS_ASM_LOCK_2 (esc)				\
  xchgl	esc%r12d, (esc%r13);			\
92:

/* lock; cmpxchgl %r12d, (%r13) */
#define __ERS_ASM_CMPXCHGL(esc, lock) \
  _ERS_ASM_LOCK_1 (esc)				\
  cmpxchgl	esc%r12d, (esc%r13);		\
  _ERS_ASM_LOCK_2 (esc)				\
  lock;	cmpxchgl	esc%r12d, (esc%r13);	\
92:

#define _ERS_ASM_OP_IR_M(op, p, esc, lock, ir, m) \
  leaq	-8(esc%rsp), esc%rsp;			\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  pushq	esc%r12;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%r12, 0);		\
  pushq	esc%r13;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);		\
  _ERS_CFI_REL_OFFSET (esc%r13, 0);		\
  leaq	m, esc%r13;				\
  movq	esc%r13, 16(esc%rsp);			\
  movq	(esc%rsp), esc%r13;			\
  movl	ir, esc%r12d;				\
  movq	16(esc%rsp), esc%r13;			\
  __ERS_ASM_##op (esc, lock)			\
  p (movl	esc%r12d, 24(esc%rsp));		\
  popq	esc%r13;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%r13);			\
  popq	esc%r12;				\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);		\
  _ERS_CFI_RESTORE (esc%r12);			\
  leaq	8(esc%rsp), esc%rsp;			\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);

#define _ERS_ASM_CMPL(esc, ir, m) \
  _ERS_ASM_PUSH_FRAME (esc, 93)					\
  _ERS_ASM_OP_IR_M (CMPL, ERS_OMIT, esc, ERS_NONE, ir, m)	\
  _ERS_ASM_POP_FRAME (esc, 0)
#define _ERS_ASM_MOVL_SV(esc, ir, m) \
  _ERS_ASM_PUSH_FRAME (esc, 93)					\
  _ERS_ASM_OP_IR_M (MOVL_SV, ERS_OMIT, esc, ERS_NONE, ir, m)	\
  _ERS_ASM_POP_FRAME (esc, 0)

#define _ERS_ASM_MOVL_LD(esc, m, r) \
  _ERS_ASM_PUSH_FRAME (esc, 93)					\
  leaq	-8(esc%rsp), esc%rsp;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);				\
  pushq	esc%r12;						\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);				\
  _ERS_CFI_REL_OFFSET (esc%r12, 0);				\
  pushq	esc%r13;						\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);				\
  _ERS_CFI_REL_OFFSET (esc%r13, 0);				\
  leaq	m, esc%r13;						\
  __ERS_ASM_MOVL_LD (esc)					\
  movl	esc%r12d, 16(esc%rsp);					\
  popq	esc%r13;						\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);				\
  _ERS_CFI_RESTORE (esc%r13);					\
  popq	esc%r12;						\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);				\
  _ERS_CFI_RESTORE (esc%r12);					\
  /* We lost previous value of r here.  */			\
  movl	(esc%rsp), r;						\
  _ERS_CFI_UNDEFINED (esc%rip);					\
  _ERS_ASM_POP_FRAME (esc, 8)

#define _ERS_ASM_DECL(esc, lock, m) \
  _ERS_ASM_PUSH_FRAME (esc, 93)					\
  pushq esc%r13;						\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);				\
  _ERS_CFI_REL_OFFSET (esc%r13, 0);				\
  leaq	m, esc%r13;						\
  __ERS_ASM_DECL (esc, lock)					\
  popq	esc%r13;						\
  _ERS_CFI_ADJUST_CFA_OFFSET (-8);				\
  _ERS_CFI_RESTORE (esc%r13);					\
  _ERS_ASM_POP_FRAME (esc, 0)

#define _ERS_ASM_XCHGL(esc, r, m) \
  _ERS_ASM_PUSH_FRAME (esc, 93)					\
  leaq	-8(esc%rsp), esc%rsp;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);				\
  _ERS_ASM_OP_IR_M (XCHGL, _ERS_EVAL, esc, ERS_NONE, r, m)	\
  movl	(esc%rsp), r;						\
  _ERS_CFI_UNDEFINED (esc%rip);					\
  _ERS_ASM_POP_FRAME (esc, 8)

#define _ERS_ASM_CMPXCHGL(esc, lock, r, m) \
  _ERS_ASM_PUSH_FRAME (esc, 93)					\
  leaq	-8(esc%rsp), esc%rsp;					\
  _ERS_CFI_ADJUST_CFA_OFFSET (8);				\
  _ERS_ASM_OP_IR_M (CMPXCHGL, _ERS_EVAL, esc, lock, r, m)	\
  movl	(esc%rsp), r;						\
  _ERS_CFI_UNDEFINED (esc%rip);					\
  _ERS_ASM_POP_FRAME (esc, 8)

#define ERS_ASM_CMPL(ir, m) \
  _ERS_ASM_CMPL (ERS_NONE, ir, m)
#define ERS_ASM_MOVL_SV(ir, m) \
  _ERS_ASM_MOVL_SV (ERS_NONE, ir, m)
#define ERS_ASM_MOVL_LD(m, r) \
  _ERS_ASM_MOVL_LD (ERS_NONE, m, r)
#define ERS_ASM_DECL(lock, m) \
  _ERS_ASM_DECL (ERS_NONE, lock, m)
#define ERS_ASM_XCHGL(r, m) \
  _ERS_ASM_XCHGL (ERS_NONE, r, m)
#define ERS_ASM_CMPXCHGL(lock, r, m) \
  _ERS_ASM_CMPXCHGL (ERS_NONE, lock, r, m)

#ifndef __ASSEMBLER__

#define ERS_ASM_SCMPL(ir, m) \
  _ERS_STR (_ERS_ASM_CMPL (ERS_NONE, ir, m))
#define ERS_ASM_SMOVL_SV(ir, m) \
  _ERS_STR (_ERS_ASM_MOVL_SV (ERS_NONE, ir, m))
#define ERS_ASM_SMOVL_LD(m, r) \
  _ERS_STR (_ERS_ASM_MOVL_LD (ERS_NONE, m, r))
#define ERS_ASM_SDECL(lock, m) \
  _ERS_STR (_ERS_ASM_DECL (ERS_NONE, lock, m))
#define ERS_ASM_SXCHGL(r, m) \
  _ERS_STR (_ERS_ASM_XCHGL (ERS_NONE, r, m))
#define ERS_ASM_SCMPXCHGL(lock, r, m) \
  _ERS_STR (_ERS_ASM_CMPXCHGL (ERS_NONE, lock, r, m))

#define ERS_ASM_ESSYSCALL \
  _ERS_STR (_ERS_ASM_SYSCALL (%, 0))

#define ERS_ASM_ESCMPL(ir, m) \
  _ERS_STR (_ERS_ASM_CMPL (%, ir, m))
#define ERS_ASM_ESMOVL_SV(ir, m) \
  _ERS_STR (_ERS_ASM_MOVL_SV (%, ir, m))
#define ERS_ASM_ESMOVL_LD(m, r) \
  _ERS_STR (_ERS_ASM_MOVL_LD (%, m, r))
#define ERS_ASM_ESDECL(lock, m) \
  _ERS_STR (_ERS_ASM_DECL (%, lock, m))
#define ERS_ASM_ESXCHGL(r, m) \
  _ERS_STR (_ERS_ASM_XCHGL (%, r, m))
#define ERS_ASM_ESCMPXCHGL(lock, r, m) \
  _ERS_STR (_ERS_ASM_CMPXCHGL (%, lock, r, m))

#endif

#endif
