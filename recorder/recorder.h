#ifndef ERS_RECORDER_H
#define ERS_RECORDER_H

struct ers_thread;

struct ers_recorder
{
  char initialized;

  void (*init_process) (struct ers_recorder *self);

  struct ers_thread *(*init_thread) (struct ers_recorder *self);
  void (*fini_thread) (struct ers_recorder *self, struct ers_thread *th);

  void (*debug) (struct ers_recorder *self, struct ers_thread *th, const char *text);

  void (*atomic_lock) (struct ers_recorder *self, struct ers_thread *th, void *mem, int size, int mo);
  void (*atomic_unlock) (struct ers_recorder *self, void *mem);
  void (*atomic_barrier) (struct ers_recorder *self, struct ers_thread *th, int mo);

  struct ers_internal* internal;
};

extern struct ers_recorder *ers_get_recorder (void);

#define ERS_INIT_PROCESS() \
  do { if (ers_get_recorder ()) ers_get_recorder ()->init_process (ers_get_recorder ()); } while (0)
#define ERS_INITIALIZED() \
  (ers_get_recorder () && ers_get_recorder ()->initialized)

#define ERS_INIT_THREAD() \
  (ers_get_recorder () ? ers_get_recorder ()->init_thread (ers_get_recorder ()) : 0)

#define ERS_DEBUG(th, text) \
  do { if (ers_get_recorder ()) ers_get_recorder ()->debug(ers_get_recorder (), th, text); } while (0)


#define ERS_ATOMIC_RELAXED 0
// #define ERS_ATOMIC_CONSUME 1
#define ERS_ATOMIC_ACQUIRE 2
#define ERS_ATOMIC_RELEASE 3
#define ERS_ATOMIC_ACQ_REL 4
#define ERS_ATOMIC_SEQ_CST 5

#define ERS_ATOMIC_COMPARE_EXCHANGE_VAL(th, mem, oldval, newval, succ_mo, fail_mo) \
  ({										\
    struct ers_thread *__ers1_th = th;						\
    typeof (mem) __ers1_m = mem;						\
    typeof (*__ers1_m) __ers1_ov = (typeof (*__ers1_m)) (oldval);		\
    typeof (*__ers1_m) __ers1_nv = (typeof (*__ers1_m)) (newval);		\
    int __ers1_succ_mo = succ_mo;						\
    int __ers1_fail_mo = fail_mo;						\
    typeof (*__ers1_m) __ers1_result;						\
    struct ers_recorder *__ers1_recorder = ers_get_recorder ();			\
    __ers1_recorder->atomic_lock (__ers1_recorder, __ers1_th,			\
				  (void *) __ers1_m, sizeof *__ers1_m,		\
				  *__ers1_m == __ers1_ov			\
				  ? __ers1_succ_mo : __ers1_fail_mo);		\
    __ers1_result = *__ers1_m;							\
    if (*__ers1_m == __ers1_ov) *__ers1_m = __ers1_nv;				\
    __ers1_recorder->atomic_unlock (__ers1_recorder, (void *) __ers1_m);	\
    __ers1_result;								\
  })

#define ERS_ATOMIC_COMPARE_EXCHANGE_BOOL(th, mem, oldval, newval, succ_mo, fail_mo) \
  ({										\
    struct ers_thread *__ers2_th = th;						\
    typeof (mem) __ers2_m = mem;						\
    typeof (*__ers2_m) __ers2_ov = (typeof (*__ers2_m)) (oldval);		\
    typeof (*__ers2_m) __ers2_nv = (typeof (*__ers2_m)) (newval);		\
    int __ers2_succ_mo = succ_mo;						\
    int __ers2_fail_mo = fail_mo;						\
    char __ers2_result;								\
    struct ers_recorder *__ers2_recorder = ers_get_recorder ();			\
    __ers2_recorder->atomic_lock (__ers2_recorder, __ers2_th,			\
				  (void *) __ers2_m, sizeof *__ers2_m,		\
				  *__ers2_m == __ers2_ov			\
				  ? __ers2_succ_mo : __ers2_fail_mo);		\
    __ers2_result = *__ers2_m == __ers2_ov;					\
    if (__ers2_result) *__ers2_m = __ers2_nv;					\
    __ers2_recorder->atomic_unlock (__ers2_recorder, (void *) __ers2_m);	\
    __ers2_result;								\
  })

#define _ERS_ATOMIC_OP(th, mem, value, mo, op) \
  ({										\
    struct ers_thread *__ers3_th = th;						\
    typeof (mem) __ers3_m = mem;						\
    typeof (*__ers3_m) __ers3_v = (typeof (*__ers3_m)) (value);			\
    int __ers3_mo = mo;								\
    typeof (*__ers3_m) __ers3_result;						\
    struct ers_recorder *__ers3_recorder = ers_get_recorder ();			\
    __ers3_recorder->atomic_lock (__ers3_recorder, __ers3_th,			\
				  (void *) __ers3_m, sizeof *__ers3_m,		\
				  __ers3_mo);					\
    __ers3_result = *__ers3_m;							\
    *__ers3_m = op (*__ers3_m, __ers3_v);					\
    __ers3_recorder->atomic_unlock (__ers3_recorder, (void *) __ers3_m);	\
    __ers3_result;								\
  })

#define _ERS_ATOMIC_OP_CHANGE(oldval, newval) (newval)
#define _ERS_ATOMIC_OP_ADD(oldval, newval) ((oldval) + (newval))
#define _ERS_ATOMIC_OP_AND(oldval, newval) ((oldval) & (newval))
#define _ERS_ATOMIC_OP_OR(oldval, newval) ((oldval) | (newval))
#define _ERS_ATOMIC_OP_XOR(oldval, newval) ((oldval) ^ (newval))

#define ERS_ATOMIC_EXCHANGE(th, mem, value, mo) \
  _ERS_ATOMIC_OP (th, mem, value, mo, _ERS_ATOMIC_OP_CHANGE)
#define ERS_ATOMIC_FETCH_ADD(th, mem, value, mo) \
  _ERS_ATOMIC_OP (th, mem, value, mo, _ERS_ATOMIC_OP_ADD)
#define ERS_ATOMIC_FETCH_AND(th, mem, value, mo) \
  _ERS_ATOMIC_OP (th, mem, value, mo, _ERS_ATOMIC_OP_AND)
#define ERS_ATOMIC_FETCH_OR(th, mem, value, mo) \
  _ERS_ATOMIC_OP (th, mem, value, mo, _ERS_ATOMIC_OP_OR)
#define ERS_ATOMIC_FETCH_XOR(th, mem, value, mo) \
  _ERS_ATOMIC_OP (th, mem, value, mo, _ERS_ATOMIC_OP_XOR)

#define _ERS_ATOMIC_OP_SUB_IF_POS(oldval, newval) \
  ({										\
    typeof (oldval) __ers4_ov = oldval;						\
    typeof (newval) __ers4_nv = newval;						\
    __ers4_ov > __ers4_nv							\
      ? __ers4_ov - __ers4_nv : __ers4_ov;					\
  })

#define ERS_ATOMIC_DECREMENT_IF_POSITIVE(th, mem) \
  _ERS_ATOMIC_OP (th, mem, 1, ERS_ATOMIC_SEQ_CST, _ERS_ATOMIC_OP_SUB_IF_POS)

#define ERS_ATOMIC_LOAD(th, mem, mo) \
  ({										\
    struct ers_thread *__ers5_th = th;						\
    typeof (mem) __ers5_m = mem;						\
    int __ers5_mo = mo;								\
    typeof (*__ers5_m) __ers5_result;						\
    struct ers_recorder *__ers5_recorder = ers_get_recorder ();			\
    __ers5_recorder->atomic_lock (__ers5_recorder, __ers5_th,			\
				  (void *) __ers5_m, sizeof *__ers5_m,		\
				  __ers5_mo);					\
    __ers5_result = *__ers5_m;							\
    __ers5_recorder->atomic_unlock (__ers5_recorder, (void *) __ers5_m);	\
    __ers5_result;								\
  })

#define ERS_ATOMIC_STORE(th, mem, value, mo) \
  do {										\
    struct ers_thread *__ers6_th = th;						\
    typeof (mem) __ers6_m = mem;						\
    typeof (*__ers6_m) __ers6_v = (typeof (*__ers6_m)) (value);			\
    int __ers6_mo = mo;								\
    struct ers_recorder *__ers6_recorder = ers_get_recorder ();			\
    __ers6_recorder->atomic_lock (__ers6_recorder, __ers6_th,			\
				  (void *) __ers6_m, sizeof *__ers6_m,		\
				  __ers6_mo);					\
    *__ers6_m = __ers6_v;							\
    __ers6_recorder->atomic_unlock (__ers6_recorder, (void *) __ers6_m);	\
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

#define ERS_ATOMIC_MAX(th, mem, value) \
  (void) _ERS_ATOMIC_OP (th, mem, value, ERS_ATOMIC_SEQ_CST, _ERS_ATOMIC_OP_MAX)
#define ERS_ATOMIC_MIN(th, mem, value) \
  (void) _ERS_ATOMIC_OP (th, mem, value, ERS_ATOMIC_SEQ_CST, _ERS_ATOMIC_OP_MIN)

#define ERS_ATOMIC_BARRIER(th, mo) \
  ers_get_recorder ()->atomic_barrier (ers_get_recorder (), th, mo)

#define ERS_ATOMIC_COMPARE_EXCHANGE(th, mem, expected, desired, succ_mo, fail_mo) \
  ({ typeof (expected) __ers80_e = expected;					\
     typeof (*__ers80_e) __ers80_ev = *__ers80_e;				\
     *__ers80_e =								\
       ERS_ATOMIC_COMPARE_EXCHANGE_VAL (th, mem, __ers80_ev, desired,		\
					succ_mo, fail_mo);			\
     *__ers80_e == __ers80_ev;							\
   })


#define ers_atomic_compare_and_exchange_val_acq(th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (th, mem, oldval, newval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_compare_and_exchange_val_acq(th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (th, mem, oldval, newval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_compare_and_exchange_val_rel(th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (th, mem, oldval, newval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_compare_and_exchange_val_rel(th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (th, mem, oldval, newval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_compare_and_exchange_bool_acq(th, mem, newval, oldval) \
  /* As __sync_bool_compare_and_swap */						\
  (! ERS_ATOMIC_COMPARE_EXCHANGE_BOOL (th, mem, oldval, newval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST))
#define ers_catomic_compare_and_exchange_bool_acq(th, mem, newval, oldval) \
  /* As __sync_bool_compare_and_swap */						\
  (! ERS_ATOMIC_COMPARE_EXCHANGE_BOOL (th, mem, oldval, newval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST))
#define ers_atomic_exchange_acq(th, mem, value) \
  ERS_ATOMIC_EXCHANGE (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_rel(th, mem, value) \
  ERS_ATOMIC_EXCHANGE (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add_acq(th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add_rel(th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add(th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_exchange_and_add(th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_max(th, mem, value) \
  ERS_ATOMIC_MAX (th, mem, value)
#define ers_catomic_max(th, mem, value) \
  ERS_ATOMIC_MAX (th, mem, value)
#define ers_atomic_min(th, mem, value) \
  ERS_ATOMIC_MIN (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_add(th, mem, value) \
  (void) ERS_ATOMIC_FETCH_ADD (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_add(th, mem, value) \
  (void) ERS_ATOMIC_FETCH_ADD (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_increment(th, mem) \
  (void) ERS_ATOMIC_FETCH_ADD (th, mem, 1, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_increment(th, mem) \
  (void) ERS_ATOMIC_FETCH_ADD (th, mem, 1, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_increment_val(th, mem) \
  (ERS_ATOMIC_FETCH_ADD (th, mem, 1, ERS_ATOMIC_SEQ_CST) + 1)
#define ers_catomic_increment_val(th, mem) \
  (ERS_ATOMIC_FETCH_ADD (th, mem, 1, ERS_ATOMIC_SEQ_CST) + 1)
#define ers_atomic_increment_and_test(th, mem) \
  ((ERS_ATOMIC_FETCH_ADD (th, mem, 1, ERS_ATOMIC_SEQ_CST) + 1) == 0)
#define ers_atomic_decrement(th, mem) \
  (void) ERS_ATOMIC_FETCH_ADD (th, mem, -1, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_decrement(th, mem) \
  (void) ERS_ATOMIC_FETCH_ADD (th, mem, -1, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_decrement_val(th, mem) \
  (ERS_ATOMIC_FETCH_ADD (th, mem, -1, ERS_ATOMIC_SEQ_CST) - 1)
#define ers_catomic_decrement_val(th, mem) \
  (ERS_ATOMIC_FETCH_ADD (th, mem, -1, ERS_ATOMIC_SEQ_CST) - 1)
#define ers_atomic_decrement_and_test(th, mem) \
  ((ERS_ATOMIC_FETCH_ADD (th, mem, -1, ERS_ATOMIC_SEQ_CST) - 1) == 0)
#define ers_atomic_decrement_if_positive(th, mem) \
  (ERS_ATOMIC_DECREMENT_IF_POSITIVE (th, mem))
#define ers_atomic_add_negative(th, mem, value) \
  ({ typeof (value) __ers50_v = value;						\
     ERS_ATOMIC_FETCH_ADD (th, mem, __ers50_v, ERS_ATOMIC_SEQ_CST) < -__ers50_v; })
#define ers_atomic_add_zero(th, mem, value) \
  ({ typeof (value) __ers60_v = value;						\
     ERS_ATOMIC_FETCH_ADD (th, mem, __ers60_v, ERS_ATOMIC_SEQ_CST) == -__ers60_v; })
#define ers_atomic_bit_set(th, mem, bit) \
  (void) ERS_ATOMIC_FETCH_OR (th, mem, ((typeof (*(mem))) 1 << (bit)), ERS_ATOMIC_SEQ_CST)
#define ers_atomic_bit_test_set(th, mem, bit) \
  ({ typeof (*mem) __ers70_mask = ((typeof (*(mem))) 1 << (bit));		\
     ERS_ATOMIC_FETCH_OR (th, mem, __ers70_mask, ERS_ATOMIC_SEQ_CST) & __ers70_mask; })
#define ers_atomic_and(th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_AND (th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_and(th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_AND (th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_and_val(th, mem, mask) \
  ERS_ATOMIC_FETCH_AND (th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_or(th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_OR (th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_or(th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_OR (th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_or_val(th, mem, mask) \
  ERS_ATOMIC_FETCH_OR (th, mem, mask, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_full_barrier(th) ERS_ATOMIC_BARRIER (th, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_read_barrier(th) ERS_ATOMIC_BARRIER (th, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_write_barrier(th) ERS_ATOMIC_BARRIER (th, ERS_ATOMIC_RELEASE)
#define ers_atomic_forced_read(th, x) \
  ERS_ATOMIC_LOAD (th, &(x), ERS_ATOMIC_SEQ_CST)
#define ers_atomic_thread_fence_acquire(th) ERS_ATOMIC_BARRIER (th, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_thread_fence_release(th) ERS_ATOMIC_BARRIER (th, ERS_ATOMIC_RELEASE)
#define ers_atomic_thread_fence_seq_cst(th) ERS_ATOMIC_BARRIER (th, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_load_relaxed(th, mem) \
  ERS_ATOMIC_LOAD (th, mem, ERS_ATOMIC_RELAXED)
#define ers_atomic_load_acquire(th, mem) \
  ERS_ATOMIC_LOAD (th, mem, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_store_relaxed(th, mem, val) \
  ERS_ATOMIC_STORE (th, mem, val, ERS_ATOMIC_RELAXED)
#define ers_atomic_store_release(th, mem, val) \
  ERS_ATOMIC_STORE (th, mem, val, ERS_ATOMIC_RELEASE)
#define ers_atomic_compare_exchange_weak_relaxed(th, mem, expected, desired) \
  ERS_ATOMIC_COMPARE_EXCHANGE (th, mem, expected, desired, ERS_ATOMIC_ACQUIRE, ERS_ATOMIC_RELAXED)
#define ers_atomic_compare_exchange_weak_acquire(th, mem, expected, desired) \
  ERS_ATOMIC_COMPARE_EXCHANGE (th, mem, expected, desired, ERS_ATOMIC_ACQUIRE, ERS_ATOMIC_RELAXED)
#define ers_atomic_compare_exchange_weak_release(th, mem, expected, desired) \
  ERS_ATOMIC_COMPARE_EXCHANGE (th, mem, expected, desired, ERS_ATOMIC_RELEASE, ERS_ATOMIC_RELAXED)
#define ers_atomic_exchange_relaxed(th, mem, desired) \
  ERS_ATOMIC_EXCHANGE (th, mem, desired, ERS_ATOMIC_RELAXED)
#define ers_atomic_exchange_acquire(th, mem, desired) \
  ERS_ATOMIC_EXCHANGE (th, mem, desired, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_exchange_release(th, mem, desired) \
  ERS_ATOMIC_EXCHANGE (th, mem, desired, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_add_relaxed(th, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (th, mem, operand, ERS_ATOMIC_RELAXED)
#define ers_atomic_fetch_add_acquire(th, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (th, mem, operand, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_fetch_add_release(th, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (th, mem, operand, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_add_acq_rel(th, mem, operand) \
  ERS_ATOMIC_FETCH_ADD (th, mem, operand, ERS_ATOMIC_ACQ_REL)
#define ers_atomic_fetch_and_relaxed(th, mem, operand) \
  ERS_ATOMIC_FETCH_AND (th, mem, operand, ERS_ATOMIC_RELAXED)
#define ers_atomic_fetch_and_acquire(th, mem, operand) \
  ERS_ATOMIC_FETCH_AND (th, mem, operand, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_fetch_and_release(th, mem, operand) \
  ERS_ATOMIC_FETCH_AND (th, mem, operand, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_or_relaxed(th, mem, operand) \
  ERS_ATOMIC_FETCH_OR (th, mem, operand, ERS_ATOMIC_RELAXED)
#define ers_atomic_fetch_or_acquire(th, mem, operand) \
  ERS_ATOMIC_FETCH_OR (th, mem, operand, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_fetch_or_release(th, mem, operand) \
  ERS_ATOMIC_FETCH_OR (th, mem, operand, ERS_ATOMIC_RELEASE)
#define ers_atomic_fetch_xor_release(th, mem, operand) \
  ERS_ATOMIC_FETCH_XOR (th, mem, operand, ERS_ATOMIC_RELEASE)

#endif
