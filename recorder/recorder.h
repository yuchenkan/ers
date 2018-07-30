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

#if 0
// x86_64
#define ers_atomic_compare_and_exchange_val_acq(th, mem, newval, oldval) (newval)
#define ers_atomic_compare_and_exchange_bool_acq(th, mem, newval, oldval) 0

#define ers___arch_c_compare_and_exchange_val_8_acq(th, mem, newval, oldval) \
  ers_atomic_compare_and_exchange_val_acq (th, mem, newval, oldval)
#define ers___arch_c_compare_and_exchange_val_16_acq(th, mem, newval, oldval) \
  ers_atomic_compare_and_exchange_val_acq (th, mem, newval, oldval)
#define ers___arch_c_compare_and_exchange_val_32_acq(th, mem, newval, oldval) \
  ers_atomic_compare_and_exchange_val_acq (th, mem, newval, oldval)
#define ers___arch_c_compare_and_exchange_val_64_acq(th, mem, newval, oldval) \
  ers_atomic_compare_and_exchange_val_acq (th, mem, newval, oldval)

#define ers_atomic_exchange_acq(th, mem, newvalue) (newval)

#define ers___arch_exchange_and_add_body(th, lock, mem, value)
#define ers_atomic_exchange_and_add(th, mem, value) (value)

#define ers___arch_add_body1(th, lock, mem, value) do { } while (0)
#define ers_atomic_add_negative(th, mem, value) ((unsigned char) 0)
#define ers_atomic_add_zero(th, mem, value) ((unsigned char) 0)

#define ers___arch_increment_body(th, lock, mem) do { } while (0)
#define ers_atomic_increment_and_test(th, mem) ((unsigned char) 0)
#define ers_atomic_decrement_body(th, mem) do { } while (0)
#define ers_atomic_decrement_and_test(th, mem) ((unsigned char) 0)

#define ers_atomic_bit_set(th, mem, bit) do { } while (0)
#define ers_atomic_bit_test_set(th, mem, bit) ((unsigned char) 0)
#endif

#define ers_atomic_compare_and_exchange_val_acq(th, mem, newval, oldval) 0
#define ers_catomic_compare_and_exchange_val_acq(th, mem, newval, oldval) 0
#define ers_catomic_compare_and_exchange_val_rel(th, mem, newval, oldval) 0
#define ers_atomic_compare_and_exchange_val_rel(th, mem, newval, oldval) 0
#define ers_atomic_compare_and_exchange_bool_acq(th, mem, newval, oldval) 0
#define ers_catomic_compare_and_exchange_bool_acq(th, mem, newval, oldval) 0
#define ers_atomic_exchange_acq(th, mem, newvalue) (newvalue)
#define ers_atomic_exchange_rel(th, mem, newvalue) (newvalue)
#define ers_atomic_exchange_and_add_acq(th, mem, value) (value)
#define ers_atomic_exchange_and_add_rel(th, mem, value) (value)
#define ers_atomic_exchange_and_add(th, mem, value) (value)
#define ers_catomic_exchange_and_add(th, mem, value) (value)
#define ers_atomic_max(th, mem, value) do { } while (0)
#define ers_catomic_max(th, mem, value) do { } while (0)
#define ers_atomic_min(th, mem, value) do { } while (0)
#define ers_atomic_add(th, mem, value) do { } while (0)
#define ers_catomic_add(th, mem, value) do { } while (0)
#define ers_atomic_increment(th, mem) do { } while (0)
#define ers_catomic_increment(th, mem) do { } while (0)
#define ers_atomic_increment_val(th, mem) 0
#define ers_catomic_increment_val(th, mem) 0
#define ers_atomic_increment_and_test(th, mem) 0
#define ers_atomic_decrement(th, mem) do { } while (0)
#define ers_catomic_decrement(th, mem) do { } while (0)
#define ers_atomic_decrement_val(th, mem) 0
#define ers_catomic_decrement_val(th, mem) 0
#define ers_atomic_decrement_and_test(th, mem) 0
#define ers_atomic_decrement_if_positive(th, mem) 0
#define ers_atomic_add_negative(th, mem, value) 0
#define ers_atomic_add_zero(th, mem, value) 0
#define ers_atomic_bit_set(th, mem, bit) do { } while (0)
#define ers_atomic_bit_test_set(th, mem, bit) 0
#define ers_atomic_and(th, mem, mask) do { } while (0)
#define ers_catomic_and(th, mem, mask) do { } while (0)
#define ers_atomic_and_val(th, mem, mask) 0
#define ers_atomic_or(th, mem, mask) do { } while (0)
#define ers_catomic_or(th, mem, mask) do { } while (0)
#define ers_atomic_or_val(th, mem, mask) 0
#define ers_atomic_full_barrier(th) do { } while (0)
#define ers_atomic_read_barrier(th) do { } while (0)
#define ers_atomic_write_barrier(th) do { } while (0)
#define ers_atomic_forced_read(th, x) 0
#define ers_atomic_thread_fence_acquire(th) do { } while (0)
#define ers_atomic_thread_fence_release(th) do { } while (0)
#define ers_atomic_thread_fence_seq_cst(th) do { } while (0)
#define ers_atomic_load_relaxed(th, mem) 0
#define ers_atomic_load_acquire(th, mem) 0
#define ers_atomic_store_relaxed(th, mem, val) do { } while (0)
#define ers_atomic_store_release(th, mem, val) do { } while (0)
#define ers_atomic_compare_exchange_weak_relaxed(th, mem, expected, desired) 0
#define ers_atomic_compare_exchange_weak_acquire(th, mem, expected, desired) 0
#define ers_atomic_compare_exchange_weak_release(th, mem, expected, desired) 0
#define ers_atomic_exchange_relaxed(th, mem, desired) 0
#define ers_atomic_exchange_acquire(th, mem, desired) 0
#define ers_atomic_exchange_release(th, mem, desired) 0
#define ers_atomic_fetch_add_relaxed(th, mem, operand) 0
#define ers_atomic_fetch_add_acquire(th, mem, operand) 0
#define ers_atomic_fetch_add_release(th, mem, operand) 0
#define ers_atomic_fetch_add_acq_rel(th, mem, operand) 0
#define ers_atomic_fetch_and_relaxed(th, mem, operand) 0
#define ers_atomic_fetch_and_acquire(th, mem, operand) 0
#define ers_atomic_fetch_and_release(th, mem, operand) 0
#define ers_atomic_fetch_or_relaxed(th, mem, operand) 0
#define ers_atomic_fetch_or_acquire(th, mem, operand) 0
#define ers_atomic_fetch_or_release(th, mem, operand) 0
#define ers_atomic_fetch_xor_release(th, mem, operand) 0

#endif
