/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#include <m4_lock_h>
#include <m4_syscall_h>
#include <m4_atomic_h>

void
m4_ns(assert_lock, _) (struct eri_lock *lock)
{
  m4_ns(atomic_inc) (&lock->wait, 1);
  do
    {
      uint64_t res = m4_ns(syscall) (futex, &lock->lock,
				     ERI_FUTEX_WAIT, 1, 0);
      eri_assert (! eri_syscall_is_error (res)
		  || res == ERI_EAGAIN || res == ERI_EINTR);
    }
  while (m4_ns(atomic_exchange) (&lock->lock, 1, 0));
  m4_ns(atomic_dec) (&lock->wait, 1);
}

void
m4_ns(assert_unlock, _) (struct eri_lock *lock)
{
  m4_ns(assert_syscall) (futex, &lock->lock, ERI_FUTEX_WAKE, 1);
}
