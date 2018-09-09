#include "syscall.h"

void
eri_lock (int *lock, char futex)
{
  while (__atomic_exchange_n (lock, 1, __ATOMIC_ACQUIRE))
    if (futex)
      {
	long res = ERI_SYSCALL (futex, lock, ERI_FUTEX_WAIT, 1, 0);
	eri_assert (! ERI_SYSCALL_ERROR_P (res) || -res == ERI_EAGAIN);
      }
}

void
eri_unlock (int *lock, char futex)
{
  __atomic_store_n (lock, 0, __ATOMIC_RELEASE);
  if (futex)
    ERI_ASSERT_SYSCALL (futex, lock, ERI_FUTEX_WAKE, 1);
}
