#include "lib/syscall.h"
#include "lib/atomic.h"

void
eri_lock (int32_t *lock)
{
  while (eri_atomic_exchange (lock, 1))
    {
      uint64_t res = eri_syscall (futex, lock, ERI_FUTEX_WAIT, 1, 0);
      eri_assert (! eri_syscall_is_error (res) || res == ERI_EAGAIN);
    }
  eri_barrier ();
}

void
eri_unlock (int32_t *lock)
{
  eri_barrier ();
  eri_atomic_store (lock, 0);
  eri_assert_syscall (futex, lock, ERI_FUTEX_WAKE, 1);
}
