#include <lib/lock.h>
#include <lib/syscall.h>
#include <lib/atomic.h>

void
eri_assert_lock (struct eri_lock *lock)
{
  while (eri_atomic_exchange (&lock->lock, 1))
    {
      uint64_t res = eri_syscall (futex, &lock->lock, ERI_FUTEX_WAIT, 1, 0);
      eri_assert (! eri_syscall_is_error (res)
		  || res == ERI_EAGAIN || res == ERI_EINTR);
    }
  eri_barrier ();
}

void
eri_assert_unlock (struct eri_lock *lock)
{
  eri_barrier ();
  eri_atomic_store (&lock->lock, 0);
  eri_assert_syscall (futex, &lock->lock, ERI_FUTEX_WAKE, 1);
}
