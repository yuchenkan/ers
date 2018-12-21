#include "lib/syscall.h"

void
eri_lock (int32_t *lock)
{
  while (eri_atomic_exchange (lock, 1))
    {
      uint64_t res = ERI_SYSCALL (futex, lock, ERI_FUTEX_WAIT, 1, 0);
      eri_assert (! ERI_SYSCALL_IS_ERROR (res) || -res == ERI_EAGAIN);
    }
}

void
eri_unlock (int32_t *lock)
{
  eri_atomic_store (lock, 0);
  ERI_ASSERT_SYSCALL (futex, lock, ERI_FUTEX_WAKE, 1);
}
