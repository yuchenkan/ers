#ifndef ERS_RECORDER_H
#define ERS_RECORDER_H

#ifndef __ASSEMBLER__

struct ers_thread;

struct ers_recorder
{
  char initialized;

  void (*init_process) (struct ers_recorder *self);

  struct ers_thread *(*init_thread) (struct ers_recorder *self);
  void (*fini_thread) (struct ers_thread *th);

  long (*syscall) (struct ers_thread *th, struct ers_thread *new_th, int nr,
		   long a1, long a2, long a3, long a4, long a5, long a6);

  void (*atomic_lock) (struct ers_thread *th, void *mem, int size, int mo);
  void (*atomic_unlock) (struct ers_thread *th, void *mem);
  void (*atomic_barrier) (struct ers_thread *th, int mo);

  void (*debug) (struct ers_thread *th, const char *text);

  struct ers_internal* internal;
};

extern struct ers_recorder *ers_get_recorder (void);

#define ERS_INIT_PROCESS_X() \
  do { struct ers_recorder *__ers_recorder = ers_get_recorder ();		\
       if (__ers_recorder) __ers_recorder->init_process (__ers_recorder); } while (0)
#define ERS_INIT_THREAD_X() \
  ({ struct ers_recorder *__ers_recorder = ers_get_recorder ();			\
     __ers_recorder ? __ers_recorder->init_thread (__ers_recorder) : 0; })
#define ERS_FINI_THREAD_X(th) \
  do { struct ers_recorder *__ers_recorder = ers_get_recorder ();		\
       if (__ers_recorder) __ers_recorder->fini_thread (th); } while (0)

#define ERS_REPLACE_X(macro, get_thread, ...) \
  do {										\
    struct ers_recorder *__ers_recorder = ers_get_recorder ();			\
    struct ers_thread *__ers_thread;						\
    if (__ers_recorder && __ers_recorder->initialized				\
	&& (__ers_thread = get_thread ()))	      				\
      ers_##macro (__ers_recorder, __ers_thread, ##__VA_ARGS__);		\
    else									\
      _##macro (__VA_ARGS__);							\
  } while (0)

#define ERS_REPLACE_EXP_X(macro, get_thread, ...) \
  ({										\
    struct ers_recorder *__ers_recorder = ers_get_recorder ();			\
    struct ers_thread *__ers_thread;						\
    (__ers_recorder && __ers_recorder->initialized				\
     && (__ers_thread = get_thread ()))						\
      ? ers_##macro (__ers_recorder, __ers_thread, ##__VA_ARGS__)		\
      : _##macro (__VA_ARGS__);							\
  })

#define ers_internal_syscall0(rec, th, number, err) \
  ((rec)->syscall (th, 0, number, 0, 0, 0, 0, 0, 0))
#define ers_internal_syscall1(rec, th, number, err, a1) \
  ((rec)->syscall (th, 0, number, (long) (a1), 0, 0, 0, 0, 0))
#define ers_internal_syscall2(rec, th, number, err, a1, a2) \
  ((rec)->syscall (th, 0, number, (long) (a1), (long) (a2), 0, 0, 0, 0))
#define ers_internal_syscall3(rec, th, number, err, a1, a2, a3) \
  ((rec)->syscall (th, 0, number, (long) (a1), (long) (a2), (long) (a3), 0, 0, 0))
#define ers_internal_syscall4(rec, th, number, err, a1, a2, a3, a4) \
  ((rec)->syscall (th, 0, number, (long) (a1), (long) (a2), (long) (a3), (long) (a4), 0, 0))
#define ers_internal_syscall5(rec, th, number, err, a1, a2, a3, a4, a5) \
  ((rec)->syscall (th, 0, number, (long) (a1), (long) (a2), (long) (a3), (long) (a4), (long) (a5), 0))
#define ers_internal_syscall6(rec, th, number, err, a1, a2, a3, a4, a5, a6) \
  ((rec)->syscall (th, 0, number, (long) (a1), (long) (a2), (long) (a3), (long) (a4), (long) (a5), (long) (a6)))

#define ERS_ATOMIC_RELAXED 0
/* #define ERS_ATOMIC_CONSUME 1 */
#define ERS_ATOMIC_ACQUIRE 2
#define ERS_ATOMIC_RELEASE 3
#define ERS_ATOMIC_ACQ_REL 4
#define ERS_ATOMIC_SEQ_CST 5

#define ERS_ATOMIC_COMPARE_EXCHANGE_VAL(rec, th, mem, oldval, newval, succ_mo, fail_mo) \
  ({										\
    struct ers_recorder *__ers1_recorder = (rec);				\
    struct ers_thread *__ers1_th = th;						\
    typeof (mem) __ers1_m = mem;						\
    typeof (*__ers1_m) __ers1_ov = (typeof (*__ers1_m)) (oldval);		\
    typeof (*__ers1_m) __ers1_nv = (typeof (*__ers1_m)) (newval);		\
    int __ers1_succ_mo = succ_mo;						\
    int __ers1_fail_mo = fail_mo;						\
    typeof (*__ers1_m) __ers1_result;						\
    __ers1_recorder->atomic_lock (__ers1_th,					\
				  (void *) __ers1_m, sizeof *__ers1_m,		\
				  *__ers1_m == __ers1_ov			\
				  ? __ers1_succ_mo : __ers1_fail_mo);		\
    __ers1_result = *__ers1_m;							\
    if (*__ers1_m == __ers1_ov) *__ers1_m = __ers1_nv;				\
    __ers1_recorder->atomic_unlock (__ers1_th, (void *) __ers1_m);		\
    __ers1_result;								\
  })

#define ERS_ATOMIC_COMPARE_EXCHANGE_BOOL(rec, th, mem, oldval, newval, succ_mo, fail_mo) \
  ({										\
    struct ers_recorder *__ers2_recorder = (rec);				\
    struct ers_thread *__ers2_th = th;						\
    typeof (mem) __ers2_m = mem;						\
    typeof (*__ers2_m) __ers2_ov = (typeof (*__ers2_m)) (oldval);		\
    typeof (*__ers2_m) __ers2_nv = (typeof (*__ers2_m)) (newval);		\
    int __ers2_succ_mo = succ_mo;						\
    int __ers2_fail_mo = fail_mo;						\
    char __ers2_result;								\
    __ers2_recorder->atomic_lock (__ers2_th,					\
				  (void *) __ers2_m, sizeof *__ers2_m,		\
				  *__ers2_m == __ers2_ov			\
				  ? __ers2_succ_mo : __ers2_fail_mo);		\
    __ers2_result = *__ers2_m == __ers2_ov;					\
    if (__ers2_result) *__ers2_m = __ers2_nv;					\
    __ers2_recorder->atomic_unlock (__ers2_th, (void *) __ers2_m);		\
    __ers2_result;								\
  })

#define _ERS_ATOMIC_OP(rec, th, mem, value, mo, op) \
  ({										\
    struct ers_recorder *__ers3_recorder = (rec);				\
    struct ers_thread *__ers3_th = th;						\
    typeof (mem) __ers3_m = mem;						\
    typeof (*__ers3_m) __ers3_v = (typeof (*__ers3_m)) (value);			\
    int __ers3_mo = mo;								\
    typeof (*__ers3_m) __ers3_result;						\
    __ers3_recorder->atomic_lock (__ers3_th,					\
				  (void *) __ers3_m, sizeof *__ers3_m,		\
				  __ers3_mo);					\
    __ers3_result = *__ers3_m;							\
    *__ers3_m = op (*__ers3_m, __ers3_v);					\
    __ers3_recorder->atomic_unlock (__ers3_th, (void *) __ers3_m);		\
    __ers3_result;								\
  })

#define _ERS_ATOMIC_OP_CHANGE(oldval, newval) (newval)
#define _ERS_ATOMIC_OP_ADD(oldval, newval) ((oldval) + (newval))
#define _ERS_ATOMIC_OP_AND(oldval, newval) ((oldval) & (newval))
#define _ERS_ATOMIC_OP_OR(oldval, newval) ((oldval) | (newval))
#define _ERS_ATOMIC_OP_XOR(oldval, newval) ((oldval) ^ (newval))

#define ERS_ATOMIC_EXCHANGE(rec, th, mem, value, mo) \
  _ERS_ATOMIC_OP (rec, th, mem, value, mo, _ERS_ATOMIC_OP_CHANGE)
#define ERS_ATOMIC_FETCH_ADD(rec, th, mem, value, mo) \
  _ERS_ATOMIC_OP (rec, th, mem, value, mo, _ERS_ATOMIC_OP_ADD)
#define ERS_ATOMIC_FETCH_AND(rec, th, mem, value, mo) \
  _ERS_ATOMIC_OP (rec, th, mem, value, mo, _ERS_ATOMIC_OP_AND)
#define ERS_ATOMIC_FETCH_OR(rec, th, mem, value, mo) \
  _ERS_ATOMIC_OP (rec, th, mem, value, mo, _ERS_ATOMIC_OP_OR)
#define ERS_ATOMIC_FETCH_XOR(rec, th, mem, value, mo) \
  _ERS_ATOMIC_OP (rec, th, mem, value, mo, _ERS_ATOMIC_OP_XOR)

#define _ERS_ATOMIC_OP_SUB_IF_POS(oldval, newval) \
  ({										\
    typeof (oldval) __ers4_ov = oldval;						\
    typeof (newval) __ers4_nv = newval;						\
    __ers4_ov > __ers4_nv							\
      ? __ers4_ov - __ers4_nv : __ers4_ov;					\
  })

#define ERS_ATOMIC_DECREMENT_IF_POSITIVE(rec, th, mem) \
  _ERS_ATOMIC_OP (rec, th, mem, 1, ERS_ATOMIC_SEQ_CST, _ERS_ATOMIC_OP_SUB_IF_POS)

#define ERS_ATOMIC_LOAD(rec, th, mem, mo) \
  ({										\
    struct ers_recorder *__ers5_recorder = (rec);				\
    struct ers_thread *__ers5_th = th;						\
    typeof (mem) __ers5_m = mem;						\
    int __ers5_mo = mo;								\
    typeof (*__ers5_m) __ers5_result;						\
    __ers5_recorder->atomic_lock (__ers5_th,					\
				  (void *) __ers5_m, sizeof *__ers5_m,		\
				  __ers5_mo);					\
    __ers5_result = *__ers5_m;							\
    __ers5_recorder->atomic_unlock (__ers5_th, (void *) __ers5_m);		\
    __ers5_result;								\
  })

#define ERS_ATOMIC_STORE(rec, th, mem, value, mo) \
  do {										\
    struct ers_recorder *__ers6_recorder = (rec);				\
    struct ers_thread *__ers6_th = th;						\
    typeof (mem) __ers6_m = mem;						\
    typeof (*__ers6_m) __ers6_v = (typeof (*__ers6_m)) (value);			\
    int __ers6_mo = mo;								\
    __ers6_recorder->atomic_lock (__ers6_th,					\
				  (void *) __ers6_m, sizeof *__ers6_m,		\
				  __ers6_mo);					\
    *__ers6_m = __ers6_v;							\
    __ers6_recorder->atomic_unlock (__ers6_th, (void *) __ers6_m);		\
  } while (0)

#define _ERS_ATOMIC_OP_MAX(oldval, newval) \
  ({										\
    typeof (oldval) __ers7_ov = oldval;						\
    typeof (newval) __ers7_nv = newval;						\
    __ers7_ov > __ers7_nv ? __ers7_ov : __ers7_nv;				\
  })
#define _ERS_ATOMIC_OP_MIN(oldval, newval) \
  ({										\
    typeof (oldval) __ers8_ov = oldval;						\
    typeof (newval) __ers8_nv = newval;						\
    __ers8_ov < __ers8_nv ? __ers8_ov : __ers8_nv;				\
  })

#define ERS_ATOMIC_MAX(rec, th, mem, value) \
  (void) _ERS_ATOMIC_OP (rec, th, mem, value, ERS_ATOMIC_SEQ_CST, _ERS_ATOMIC_OP_MAX)
#define ERS_ATOMIC_MIN(rec, th, mem, value) \
  (void) _ERS_ATOMIC_OP (rec, th, mem, value, ERS_ATOMIC_SEQ_CST, _ERS_ATOMIC_OP_MIN)

#define ERS_ATOMIC_BARRIER(rec, th, mo) rec->atomic_barrier (th, mo)

#define ERS_ATOMIC_COMPARE_EXCHANGE(rec, th, mem, expected, desired, succ_mo, fail_mo) \
  ({ typeof (expected) __ers80_e = expected;					\
     typeof (*__ers80_e) __ers80_ev = *__ers80_e;				\
     *__ers80_e =								\
       ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, th, mem, __ers80_ev, desired,	\
					succ_mo, fail_mo);			\
     *__ers80_e == __ers80_ev;							\
   })


#define ers_atomic_compare_and_exchange_val_acq(rec, th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, th, mem, oldval, newval,		\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_compare_and_exchange_val_acq(rec, th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, th, mem, oldval, newval,		\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_compare_and_exchange_val_rel(rec, th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, th, mem, oldval, newval,		\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_compare_and_exchange_val_rel(rec, th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, th, mem, oldval, newval,		\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_compare_and_exchange_bool_acq(rec, th, mem, newval, oldval) \
  /* As __sync_bool_compare_and_swap */						\
  (! ERS_ATOMIC_COMPARE_EXCHANGE_BOOL (rec, th, mem, oldval, newval,		\
				       ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST))
#define ers_catomic_compare_and_exchange_bool_acq(rec, th, mem, newval, oldval) \
  /* As __sync_bool_compare_and_swap */						\
  (! ERS_ATOMIC_COMPARE_EXCHANGE_BOOL (rec, th, mem, oldval, newval,		\
				       ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST))
#define ers_atomic_exchange_acq(rec, th, mem, value) \
  ERS_ATOMIC_EXCHANGE (rec, th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_rel(rec, th, mem, value) \
  ERS_ATOMIC_EXCHANGE (rec, th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add_acq(rec, th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (rec, th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add_rel(rec, th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (rec, th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add(rec, th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (rec, th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_exchange_and_add(rec, th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (rec, th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_max(rec, th, mem, value) \
  ERS_ATOMIC_MAX (rec, th, mem, value)
#define ers_catomic_max(rec, th, mem, value) \
  ERS_ATOMIC_MAX (rec, th, mem, value)
#define ers_atomic_min(rec, th, mem, value) \
  ERS_ATOMIC_MIN (rec, th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_add(rec, th, mem, value) \
  (void) ERS_ATOMIC_FETCH_ADD (rec, th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_add(rec, th, mem, value) \
  (void) ERS_ATOMIC_FETCH_ADD (rec, th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_increment(rec, th, mem) \
  (void) ERS_ATOMIC_FETCH_ADD (rec, th, mem, 1, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_increment(rec, th, mem) \
  (void) ERS_ATOMIC_FETCH_ADD (rec, th, mem, 1, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_increment_val(rec, th, mem) \
  (ERS_ATOMIC_FETCH_ADD (rec, th, mem, 1, ERS_ATOMIC_SEQ_CST) + 1)
#define ers_catomic_increment_val(rec, th, mem) \
  (ERS_ATOMIC_FETCH_ADD (rec, th, mem, 1, ERS_ATOMIC_SEQ_CST) + 1)
#define ers_atomic_increment_and_test(rec, th, mem) \
  ((ERS_ATOMIC_FETCH_ADD (rec, th, mem, 1, ERS_ATOMIC_SEQ_CST) + 1) == 0)
#define ers_atomic_decrement(rec, th, mem) \
  (void) ERS_ATOMIC_FETCH_ADD (rec, th, mem, -1, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_decrement(rec, th, mem) \
  (void) ERS_ATOMIC_FETCH_ADD (rec, th, mem, -1, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_decrement_val(rec, th, mem) \
  (ERS_ATOMIC_FETCH_ADD (rec, th, mem, -1, ERS_ATOMIC_SEQ_CST) - 1)
#define ers_catomic_decrement_val(rec, th, mem) \
  (ERS_ATOMIC_FETCH_ADD (rec, th, mem, -1, ERS_ATOMIC_SEQ_CST) - 1)
#define ers_atomic_decrement_and_test(rec, th, mem) \
  ((ERS_ATOMIC_FETCH_ADD (rec, th, mem, -1, ERS_ATOMIC_SEQ_CST) - 1) == 0)
#define ers_atomic_decrement_if_positive(rec, th, mem) \
  (ERS_ATOMIC_DECREMENT_IF_POSITIVE (rec, th, mem))
#define ers_atomic_add_negative(rec, th, mem, value) \
  ({ typeof (value) __ers50_v = value;						\
     ERS_ATOMIC_FETCH_ADD (rec, th, mem, __ers50_v, ERS_ATOMIC_SEQ_CST) < -__ers50_v; })
#define ers_atomic_add_zero(rec, th, mem, value) \
  ({ typeof (value) __ers60_v = value;						\
     ERS_ATOMIC_FETCH_ADD (rec, th, mem, __ers60_v, ERS_ATOMIC_SEQ_CST) == -__ers60_v; })
#define ers_atomic_bit_set(rec, th, mem, bit) \
  (void) ERS_ATOMIC_FETCH_OR (rec, th, mem, ((typeof (*(mem))) 1 << (bit)), ERS_ATOMIC_SEQ_CST)
#define ers_atomic_bit_test_set(rec, th, mem, bit) \
  ({ typeof (*mem) __ers70_mask = ((typeof (*(mem))) 1 << (bit));		\
     ERS_ATOMIC_FETCH_OR (rec, th, mem, __ers70_mask, ERS_ATOMIC_SEQ_CST) & __ers70_mask; })
#define ers_atomic_and(rec, th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_AND (rec, th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_and(rec, th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_AND (rec, th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_and_val(rec, th, mem, mask) \
  ERS_ATOMIC_FETCH_AND (rec, th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_or(rec, th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_OR (rec, th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_or(rec, th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_OR (rec, th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_or_val(rec, th, mem, mask) \
  ERS_ATOMIC_FETCH_OR (rec, th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_full_barrier(rec, th) ERS_ATOMIC_BARRIER (rec, th, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_read_barrier(rec, th) ERS_ATOMIC_BARRIER (rec, th, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_write_barrier(rec, th) ERS_ATOMIC_BARRIER (rec, th, ERS_ATOMIC_RELEASE)
#define ers_atomic_forced_read(rec, th, x) \
  ERS_ATOMIC_LOAD (rec, th, &(x), ERS_ATOMIC_SEQ_CST)
#define ers_atomic_thread_fence_acquire(rec, th) \
  ERS_ATOMIC_BARRIER (rec, th, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_thread_fence_release(rec, th) \
  ERS_ATOMIC_BARRIER (rec, th, ERS_ATOMIC_RELEASE)
#define ers_atomic_thread_fence_seq_cst(rec, th) \
  ERS_ATOMIC_BARRIER (rec, th, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_load_relaxed(rec, th, mem) \
  ERS_ATOMIC_LOAD (rec, th, mem, ERS_ATOMIC_RELAXED)
#define ers_atomic_load_acquire(rec, th, mem) \
  ERS_ATOMIC_LOAD (rec, th, mem, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_store_relaxed(rec, th, mem, val) \
  ERS_ATOMIC_STORE (rec, th, mem, val, ERS_ATOMIC_RELAXED)
#define ers_atomic_store_release(rec, th, mem, val) \
  ERS_ATOMIC_STORE (rec, th, mem, val, ERS_ATOMIC_RELEASE)
#define ers_atomic_compare_exchange_weak_relaxed(rec, th, mem, expected, desired) \
  ERS_ATOMIC_COMPARE_EXCHANGE (rec, th, mem, expected, desired,			\
			       ERS_ATOMIC_ACQUIRE, ERS_ATOMIC_RELAXED)
#define ers_atomic_compare_exchange_weak_acquire(rec, th, mem, expected, desired) \
  ERS_ATOMIC_COMPARE_EXCHANGE (rec, th, mem, expected, desired,			\
			       ERS_ATOMIC_ACQUIRE, ERS_ATOMIC_RELAXED)
#define ers_atomic_compare_exchange_weak_release(rec, th, mem, expected, desired) \
  ERS_ATOMIC_COMPARE_EXCHANGE (rec, th, mem, expected, desired,			\
			       ERS_ATOMIC_RELEASE, ERS_ATOMIC_RELAXED)
#define ers_atomic_exchange_relaxed(rec, th, mem, desired) \
  ERS_ATOMIC_EXCHANGE (rec, th, mem, desired, ERS_ATOMIC_RELAXED)
#define ers_atomic_exchange_acquire(rec, th, mem, desired) \
  ERS_ATOMIC_EXCHANGE (rec, th, mem, desired, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_exchange_release(rec, th, mem, desired) \
  ERS_ATOMIC_EXCHANGE (rec, th, mem, desired, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_add_relaxed(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (rec, th, mem, operand, ERS_ATOMIC_RELAXED)
#define ers_atomic_fetch_add_acquire(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (rec, th, mem, operand, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_fetch_add_release(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (rec, th, mem, operand, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_add_acq_rel(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (rec, th, mem, operand, ERS_ATOMIC_ACQ_REL)
#define ers_atomic_fetch_and_relaxed(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_AND (rec, th, mem, operand, ERS_ATOMIC_RELAXED)
#define ers_atomic_fetch_and_acquire(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_AND (rec, th, mem, operand, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_fetch_and_release(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_AND (rec, th, mem, operand, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_or_relaxed(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_OR (rec, th, mem, operand, ERS_ATOMIC_RELAXED)
#define ers_atomic_fetch_or_acquire(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_OR (rec, th, mem, operand, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_fetch_or_release(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_OR (rec, th, mem, operand, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_xor_release(rec, th, mem, operand) \
  ERS_ATOMIC_FETCH_XOR (rec, th, mem, operand, ERS_ATOMIC_RELEASE)

#define ers_THREAD_ATOMIC_CMPXCHG_VAL(rec, th, descr, member, new, old) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (rec, th, &(descr)->member, new, old,		\
				   ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_THREAD_ATOMIC_AND(rec, th, descr, member, val) \
  (void) ERS_ATOMIC_FETCH_AND (rec, th, &(descr)->member, val, ERS_ATOMIC_SEQ_CST)
#define ers_THREAD_ATOMIC_BIT_SET(rec, th, descr, member, bit) \
  (void) ERS_ATOMIC_FETCH_OR (rec, th, &(descr)->member,			\
			      ((typeof ((descr)->member)) 1 << (bit)), ERS_ATOMIC_SEQ_CST)

#else

#define _ERS_CAT(x, y) x ## y
#define _ERS_CAT1(x, y) _ERS_CAT (x, y)

#define _ERS_NONE
#define _ERS_OMIT(...)

#define _ERS_CLONE_MAY_SKIP_CLEANUP(suffix) \
  testq	%rax, %rax;		\
  jz	._ERS_CAT (ers_done_syscall_, suffix);

#define _ERS_SYSCALL(suffix, get_thread, get_new_thread, may_skip_cleanup) \
  pushq	%rbx;									\
  pushq	%r12;									\
  pushq	%rax;			/* system call number */			\
  call	ers_get_recorder@PLT;							\
  testq	%rax, %rax;								\
  jz	._ERS_CAT (ers_null_, suffix);						\
  cmpb	$0x0, (%rax);		/* ers_recorder->initialized */			\
  je	._ERS_CAT (ers_null_, suffix);						\
  movq	%rax, %rbx;								\
  xorq	%rax, %rax;								\
  get_thread ()									\
  testq	%rax, %rax;								\
  jz	._ERS_CAT (ers_null_, suffix);						\
  movq	%rax, %r12;								\
  xorq	%rax, %rax;								\
  get_new_thread (%r8)								\
  movq	%r12, %r11;								\
  popq	%r12;									\
  pushq	%rdi;									\
  pushq	%rsi;									\
  pushq	%rdx;									\
  pushq	%r9;									\
  pushq	%r8;									\
  pushq	%r10;									\
  movq	%rdx, %r9;								\
  movq	%rsi, %r8;								\
  movq	%rdi, %rcx;								\
  movl	%r12d, %edx;		/* system call number */			\
  movq	%rax, %rsi;		/* system call number */			\
  movq	%r11, %rdi;		/* ers_thread */				\
  call	*0x20(%rbx);		/* call ers_syscall */				\
  may_skip_cleanup(suffix)							\
  popq	%r10;									\
  popq	%r8;									\
  popq	%r9;									\
  popq	%rdx;									\
  popq	%rsi;									\
  popq	%rdi;									\
  popq	%r12;									\
  popq  %rbx;									\
  jmp	._ERS_CAT (ers_done_syscall_, suffix);					\
._ERS_CAT (ers_null_, suffix):							\
  popq	%rax;									\
  popq	%r12;									\
  popq	%rbx;									\
  syscall;									\
._ERS_CAT (ers_done_syscall_, suffix):

#define ERS_SYSCALL(get_thread) \
  _ERS_SYSCALL (__COUNTER__, get_thread, _ERS_OMIT, _ERS_OMIT)
#define ERS_CLONE(get_thread, get_new_thread) \
  _ERS_SYSCALL (__COUNTER__, get_thread, get_new_thread, _ERS_CLONE_MAY_SKIP_CLEANUP)

#endif

#endif
