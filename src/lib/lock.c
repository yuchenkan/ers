#include "lib/syscall.h"

void
eri_lock (int32_t *lock)
{
  while (__atomic_exchange_n (lock, 1, __ATOMIC_ACQUIRE))
    {
      uint64_t res = ERI_SYSCALL (futex, lock, ERI_FUTEX_WAIT, 1, 0);
      eri_assert (! ERI_SYSCALL_ERROR_P (res) || -res == ERI_EAGAIN);
    }
}

void
eri_unlock (int32_t *lock)
{
  __atomic_store_n (lock, 0, __ATOMIC_RELEASE);
  ERI_ASSERT_SYSCALL (futex, lock, ERI_FUTEX_WAKE, 1);
}
