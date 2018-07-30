#ifndef ERS_RECORDER_H
#define ERS_RECORDER_H

#include <stdint.h>

struct ers_thread;

struct ers_recorder
{
  char initialized;

  void (*init_process) (struct ers_recorder *self);

  struct ers_thread *(*init_thread) (struct ers_recorder *self);
  void (*fini_thread) (struct ers_recorder *self, struct ers_thread *th);

  void (*debug) (struct ers_recorder *self, struct ers_thread *th, const char *text);
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

#define ERS_ATOMIC_COMPARE_EXCHANGE_VAL(th, mem, newval, oldval, order) 0
#define ERS_ATOMIC_COMPARE_EXCHANGE_BOOL(th, mem, newval, oldval, order) 0
#define ERS_ATOMIC_EXCHANGE(th, mem, newvalue, order) 0
#define ERS_ATOMIC_FETCH_ADD(th, mem, value, order) 0
#define ERS_ATOMIC_FETCH_AND(th, mem, value, order) 0
#define ERS_ATOMIC_FETCH_OR(th, mem, value, order) 0
#define ERS_ATOMIC_FETCH_XOR(th, mem, value, order) 0
#define ERS_ATOMIC_DECREMENT_IF_POSITIVE(th, mem, order) 0
#define ERS_ATOMIC_BIT_TEST_SET(th, mem, bit, order) 0
#define ERS_ATOMIC_LOAD(th, mem, order) 0
#define ERS_ATOMIC_STORE(th, mem, value, order) do { } while (0)
#define ERS_ATOMIC_MAX(th, mem, value, older) do { } while (0)
#define ERS_ATOMIC_MIN(th, mem, value, older) do { } while (0)
#define ERS_ATOMIC_BARRIER(order) do { } while (0)

#define ers_atomic_compare_and_exchange_val_acq(th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (th, mem, newval, oldval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_compare_and_exchange_val_acq(th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (th, mem, newval, oldval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_compare_and_exchange_val_rel(th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (th, mem, newval, oldval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_compare_and_exchange_val_rel(th, mem, newval, oldval) \
  ERS_ATOMIC_COMPARE_EXCHANGE_VAL (th, mem, newval, oldval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_compare_and_exchange_bool_acq(th, mem, newval, oldval) \
  /* As __sync_bool_compare_and_swap */						\
  (! ERS_ATOMIC_COMPARE_EXCHANGE_BOOL (th, mem, newval, oldval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST))
#define ers_catomic_compare_and_exchange_bool_acq(th, mem, newval, oldval) \
  /* As __sync_bool_compare_and_swap */						\
  (! ERS_ATOMIC_COMPARE_EXCHANGE_BOOL (th, mem, newval, oldval, ERS_ATOMIC_SEQ_CST, ERS_ATOMIC_SEQ_CST))
#define ers_atomic_exchange_acq(th, mem, newvalue) \
  ERS_ATOMIC_EXCHANGE (th, mem, newvalue, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_rel(th, mem, newvalue) \
  ERS_ATOMIC_EXCHANGE (th, mem, newvalue, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add_acq(th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add_rel(th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_exchange_and_add(th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_exchange_and_add(th, mem, value) \
  ERS_ATOMIC_FETCH_ADD (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_max(th, mem, value) \
  ERS_ATOMIC_MAX (th, mem, value, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_max(th, mem, value) \
  ERS_ATOMIC_MAX (th, mem, value, ERS_ATOMIC_SEQ_CST)
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
  (ERS_ATOMIC_DECREMENT_IF_POSITIVE (th, mem, ERS_ATOMIC_SEQ_CST))
#define ers_atomic_add_negative(th, mem, value) \
  ({ __typeof (value) __value = (value);					\
     ERS_ATOMIC_FETCH_ADD (th, mem, __value, ERS_ATOMIC_SEQ_CST) < -__value })
#define ers_atomic_add_zero(th, mem, value) \
  ({ __typeof (value) __value = (value);					\
     ERS_ATOMIC_FETCH_ADD (th, mem, __value, ERS_ATOMIC_SEQ_CST) == -__value })
#define ers_atomic_bit_set(th, mem, bit) \
  (void) ERS_ATOMIC_BIT_TEST_SET (th, mem, bit, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_bit_test_set(th, mem, bit) \
  (void) ERS_ATOMIC_BIT_TEST_SET (th, mem, bit, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_and(th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_AND (th, mem, bit, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_and(th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_AND (th, mem, bit, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_and_val(th, mem, mask) \
  ERS_ATOMIC_FETCH_AND (th, mem, bit, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_or(th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_OR (th, mem, bit, ERS_ATOMIC_SEQ_CST)
#define ers_catomic_or(th, mem, mask) \
  (void) ERS_ATOMIC_FETCH_OR (th, mem, bit, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_or_val(th, mem, mask) \
  ERS_ATOMIC_FETCH_OR (th, mem, bit, ERS_ATOMIC_SEQ_CST)
#define ers_atomic_full_barrier(th) ERS_ATOMIC_BARRIER (ERS_ATOMIC_SEQ_CST)
#define ers_atomic_read_barrier(th) ERS_ATOMIC_BARRIER (ERS_ATOMIC_ACQUIRE)
#define ers_atomic_write_barrier(th) ERS_ATOMIC_BARRIER (ERS_ATOMIC_RELEASE)
#define ers_atomic_forced_read(th, x) \
  ERS_ATOMIC_LOAD (th, &(x), ERS_ATOMIC_SEQ_CST)
#define ers_atomic_thread_fence_acquire(th) ERS_ATOMIC_BARRIER (ERS_ATOMIC_ACQUIRE)
#define ers_atomic_thread_fence_release(th) ERS_ATOMIC_BARRIER (ERS_ATOMIC_RELEASE)
#define ers_atomic_thread_fence_seq_cst(th) ERS_ATOMIC_BARRIER (ERS_ATOMIC_SEQ_CST)
#define ers_atomic_load_relaxed(th, mem) \
  ERS_ATOMIC_LOAD (th, mem, ERS_ATOMIC_RELAXED)
#define ers_atomic_load_acquire(th, mem) \
  ERS_ATOMIC_LOAD (th, mem, ERS_ATOMIC_ACQUIRE)
#define ers_atomic_store_relaxed(th, mem, val) \
  ERS_ATOMIC_STORE (th, mem, val, ERS_ATOMIC_RELAXED)
#define ers_atomic_store_release(th, mem, val) \
  ERS_ATOMIC_STORE (th, mem, val, ERS_ATOMIC_RELEASE)
#define ers_atomic_compare_exchange_weak_relaxed(th, mem, expected, desired) \
  ERS_ATOMIC_COMAPRE_EXCHANGE_BOOL (th, mem, expected, desired, ERS_ATOMIC_RELAXED, ERS_ATOMIC_RELAXED)
#define ers_atomic_compare_exchange_weak_acquire(th, mem, expected, desired) \
  ERS_ATOMIC_COMAPRE_EXCHANGE_BOOL (th, mem, expected, desired, ERS_ATOMIC_ACQUIRE, ERS_ATOMIC_RELAXED)
#define ers_atomic_compare_exchange_weak_release(th, mem, expected, desired) \
  ERS_ATOMIC_COMAPRE_EXCHANGE_BOOL (th, mem, expected, desired, ERS_ATOMIC_RELEASE, ERS_ATOMIC_RELAXED)
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
