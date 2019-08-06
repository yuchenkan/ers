/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#include <m4_lock_h>
#include <m4_syscall_h>
#include <m4_atomic_h>

void
m4_ns(assert_lock, _) (eri_lock_t *lock)
{
  m4_ns(atomic_inc) ((uint32_t *) lock + 1, 1);
  do
    {
      uint64_t res = m4_ns(syscall) (futex, lock,
				     ERI_FUTEX_WAIT, 1, 0);
      eri_assert (eri_syscall_is_ok (res)
		  || res == ERI_EAGAIN || res == ERI_EINTR);
    }
  while (m4_ns(atomic_exchange) ((uint32_t *) lock, 1, 1));
  m4_ns(atomic_dec) ((uint32_t *) lock + 1, 1);
}

void
m4_ns(assert_unlock, _) (eri_lock_t *lock)
{
  m4_ns(assert_syscall) (futex, lock, ERI_FUTEX_WAKE, 1);
}

void
m4_ns(assert_rlock, _) (eri_lock_t *lock, int32_t v)
{
  do
    {
      uint64_t res = m4_ns(syscall) (futex, lock,
				     ERI_FUTEX_WAIT, v, 0);
      eri_assert (eri_syscall_is_ok (res)
		  || res == ERI_EAGAIN || res == ERI_EINTR);
    }
  while ((v = m4_ns(atomic_load) ((uint32_t *) lock, 1)) <= 0);
}

void
m4_ns(assert_wlock, _) (eri_lock_t *lock, int32_t v)
{
  m4_ns(atomic_inc) ((uint32_t *) lock + 1, 1);
  do
    {
      uint64_t res = m4_ns(syscall) (futex, lock,
				     ERI_FUTEX_WAIT, v, 0);
      eri_assert (eri_syscall_is_ok (res)
		  || res == ERI_EAGAIN || res == ERI_EINTR);
    }
  while ((v = m4_ns(atomic_compare_exchange ((uint32_t *) lock,
					     0, -ERI_INT_MAX, 1))));
  m4_ns(atomic_dec) ((uint32_t *) lock + 1, 1);
}

void
m4_ns(assert_runlock, _) (eri_lock_t *lock)
{
  m4_ns(assert_syscall) (futex, lock, ERI_FUTEX_WAKE, 1);
}

void
m4_ns(assert_wunlock, _) (eri_lock_t *lock)
{
  m4_ns(assert_syscall) (futex, lock, ERI_FUTEX_WAKE, ERI_INT_MAX);
}
