#include "lock.h"

void
eri_lock (char replay, unsigned long tid, struct eri_lock *lock)
{
  while (__atomic_exchange_n (&lock->lock, 1, __ATOMIC_ACQUIRE))
    continue;
}

void
eri_unlock (struct eri_lock *lock)
{
  __atomic_store_n (&lock->lock, 0, __ATOMIC_RELEASE);
}
