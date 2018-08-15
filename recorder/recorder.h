#ifndef ERS_RECORDER_H
#define ERS_RECORDER_H

#ifndef __ASSEMBLER__

struct ers_thread;

struct ers_recorder /* XXX fix offset for __ASSEMBLER__ */
{
  void (*init_process) (const char *path,
			struct ers_thread *(*get) (void *),
			void (*set) (struct ers_thread *, void *),
			void *arg);

  /* 0 not replaced, 1 replaced, 2 replaced and child return */
  char (*syscall) (int nr, long a1, long a2, long a3,
		   long a4, long a5, long a6, long *res);

  char (*atomic_lock) (void *mem);
  void (*atomic_unlock) (void *mem, int mo);
  char (*atomic_barrier) (int mo);
};

extern struct ers_recorder *ers_get_recorder (void);

#define ERS_INIT_PROCESS_X(get, set, arg) \
  do {										\
    struct ers_thread *(*__ers_get) (void *) = get;				\
    void (*__ers_set) (struct ers_thread *, void *) = set;			\
    void *__ers_arg = arg;							\
    struct ers_recorder *__ers_recorder = ers_get_recorder ();			\
    if (__ers_recorder) 							\
      __ers_recorder->init_process ("ers_data",					\
				    __ers_get, __ers_set, __ers_arg);		\
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
  ERS_ATOMIC_LOAD (rec, res, &(x), ERS_ATOMIC_SEQ_CST)
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
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, res, &(descr)->member, new, old,		\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_THREAD_ATOMIC_AND(rec, descr, member, val) \
  ERS_ATOMIC_FETCH_AND (rec, 0, &(descr)->member, val, ERS_ATOMIC_SEQ_CST)
#define ers_THREAD_ATOMIC_BIT_SET(rec, descr, member, bit) \
  ERS_ATOMIC_FETCH_OR (rec, 0, &(descr)->member,			\
		       ((typeof ((descr)->member)) 1 << (bit)), ERS_ATOMIC_SEQ_CST)

#else

#define ERS_NONE

#define ERS_SYSCALL \
  pushq	%rbx;									\
  movq	%rsp, %rbx;								\
  subq	$8, %rsp;								\
  andq	$-16, %rsp;		/* align stack */				\
  movq  %rbx, (%rsp);								\
  pushq	%rax;			/* system call number */			\
  subq  $8, %rsp;								\
  call	ers_get_recorder@PLT;							\
  addq	$8, %rsp;								\
  movq	%rax, %rbx;		/* ers_recorder */				\
  testq	%rbx, %rbx;								\
  jz	92f;			/* no ers_recorder, leave 2 */			\
  movl	(%rsp), %eax;								\
  pushq	%rdi;									\
  pushq	%rsi;									\
  pushq	%rdx;									\
  pushq	%r10;									\
  pushq	%r8;									\
  subq	$8, %rsp;		/* res */					\
  pushq	%rsp;			/* &res */					\
  pushq	%r9;			/* a6 */					\
  movq	%r8, %r9;		/* a5 */					\
  movq	%r10, %r8;		/* a4 */					\
  movq	%rdx, %rcx;		/* a3 */					\
  movq	%rsi, %rdx;		/* a2 */					\
  movq	%rdi, %rsi;		/* a1 */			        	\
  movl	%eax, %edi;		/* nr */					\
  call	*0x8(%rbx);		/* call ers_recorder->syscall */		\
  cmpb	$2, %al;								\
  je	93f;			/* child, leave */				\
  testb	%al, %al;								\
  jz	91f;			/* not replaced, leave 1 */			\
  popq	%r9;									\
  movq	8(%rsp), %rax;								\
  addq	$16, %rsp;								\
  popq	%r8;									\
  popq	%r10;									\
  popq	%rdx;									\
  popq	%rsi;									\
  popq	%rdi;									\
  addq	$8, %rsp;								\
  popq  %rsp;									\
  popq	%rbx;									\
  jmp	94f;			/* replaced, leave 4 */				\
91:				/* leave 1 */					\
  popq	%r9;									\
  addq	$16, %rsp;								\
  popq	%r8;									\
  popq	%r10;									\
  popq	%rdx;									\
  popq	%rsi;									\
  popq	%rdi;									\
92:				/* leave 2 */					\
  popq	%rax;									\
  popq  %rsp;									\
  popq	%rbx;									\
  syscall;									\
  jmp	94f;									\
93:				/* child leave */				\
  xorq	%rax, %rax;								\
94:				/* leave 3 */

#define ERS_LOCK_1(mem)	\
  pushq	mem;			\
  pushq	%rbp;			\
  pushq	%rax;			\
  movq	%rsp, %rbp;		\
  subq	$8, %rsp;		\
  andq	$-16, %rsp;		\
  movq	%rbp, (%rsp);		\
  call	ers_get_recorder@PLT;	\
  testq	%rax, %rax;		\
  jz	96f;			\
				\
  pushq	%rbx;			\
  pushq	%rdi;			\
  movq	%rax, %rbx;		\
  movq	16(%rbp), %rdi;		\
  call	*16(%rbx);		\
  testb	%al, %al;		\
  jz	95f;			\
				\
  movq	16(%rbp), %rdi;

#define ERS_LOCK_2(mem)	\
  pushfq;			\
  pushq	%rsi;			\
  movl	$5, %esi;		\
  call  *24(%rbx);		\
  popq	%rsi;			\
  popfq;			\
  popq	%rdi;			\
  popq	%rbx;			\
  popq	%rsp;			\
  popq	%rax;			\
  popq	%rbp;			\
  popq	mem;			\
  jmp	97f;			\
95:				\
  popq	%rdi;			\
  popq	%rbx;			\
96:				\
  popq	%rsp;			\
  popq	%rax;			\
  popq	%rbp;			\
  popq	mem;

#define ERS_CMPL(lock, val, mem) \
  ERS_LOCK_1 (mem)		\
  cmpl	val, (%rdi);		\
  ERS_LOCK_2 (mem)		\
  lock;	cmpl	val, (mem);	\
97:

#define ERS_MOVL(lock, val, mem) \
  ERS_LOCK_1 (mem)		\
  movl	val, (%rdi);		\
  ERS_LOCK_2 (mem)		\
  lock;	movl	val, (mem);	\
97:

#define ERS_DECL(lock, mem) \
  ERS_LOCK_1 (mem)		\
  decl	(%rdi);			\
  ERS_LOCK_2 (mem)		\
  lock;	decl	(mem);		\
97:

#define ERS_XCHGL(reg, mem) \
  subq	$8, %rsp;		\
  movl	reg, (%rsp);		\
  ERS_LOCK_1 (mem)		\
				\
  movl	24(%rbp), %esi;	 	\
  xchgl	%esi, (%rdi);		\
  movl	%esi, 24(%rbp);		\
				\
  ERS_LOCK_2 (mem)		\
  movl	(%rsp), reg;		\
  addq	$8, %rsp;		\
  xchgl	reg, (mem);		\
  jmp	98f;			\
97:				\
  movl	(%rsp), reg;		\
  addq	$8, %rsp;		\
98:

#define ERS_CMPXCHGL(lock, reg, mem) \
  subq	$8, %rsp;			\
  movl	%eax, 4(%rsp);			\
  movl	reg, (%rsp);			\
  ERS_LOCK_1 (mem)			\
					\
  movl	24(%rbp), %esi;			\
  movl	28(%rbp), %eax;			\
  cmpxchgl	%esi, (%rdi);		\
  movl	%eax, 28(%rbp);			\
					\
  ERS_LOCK_2 (mem)			\
  movl	(%rsp), reg;			\
  movl	4(%rsp), %eax;			\
  addq	$8, %rsp;			\
  lock;	cmpxchgl	reg, (mem);	\
  jmp	98f;				\
97:					\
  movl	(%rsp), reg;			\
  movl	4(%rsp), %eax;			\
  addq	$8, %rsp;			\
98:


#endif

#endif
