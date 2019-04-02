/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#include <m4_lock_h>
#include <m4_syscall_h>
#include <m4_atomic_h>

void
m4_ns(assert_lock) (struct eri_lock *lock)
{
  if (! m4_ns(atomic_exchange) (&lock->lock, 1))
    {
      eri_barrier ();
      return;
    }

  m4_ns(atomic_inc) (&lock->wait);
  eri_barrier ();
  do
    {
      uint64_t res = m4_ns(syscall) (futex, &lock->lock,
				     ERI_FUTEX_WAIT, 1, 0);
      eri_assert (! eri_syscall_is_error (res)
		  || res == ERI_EAGAIN || res == ERI_EINTR);
    }
  while (m4_ns(atomic_exchange) (&lock->lock, 1));
  eri_barrier ();
  m4_ns(atomic_dec) (&lock->wait);
}

void
m4_ns(assert_unlock) (struct eri_lock *lock)
{
  eri_barrier ();
  m4_ns(atomic_store) (&lock->lock, 0);
  if (m4_ns(atomic_load_acq) (&lock->wait))
    m4_ns(assert_syscall) (futex, &lock->lock, ERI_FUTEX_WAKE, 1);
}
