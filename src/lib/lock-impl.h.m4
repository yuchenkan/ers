/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#ifndef m4_NS(LIB_LOCK_IMPL_H)
#define m4_NS(LIB_LOCK_IMPL_H)

#include <lib/compiler.h>
#include <lib/lock-common.h>
#include <m4_atomic_h>

void m4_ns(assert_lock, _) (struct eri_lock *lock);

static eri_unused void
m4_ns(assert_lock) (struct eri_lock *lock)
{
  if (! m4_ns(atomic_exchange) (&lock->lock, 1, 1)) return;
  m4_ns(assert_lock, _) (lock);
}

void m4_ns(assert_unlock, _) (struct eri_lock *lock);

static eri_unused void
m4_ns(assert_unlock) (struct eri_lock *lock)
{
  m4_ns(atomic_store) (&lock->lock, 0, 1);
  if (m4_ns(atomic_load) (&lock->wait, 0))
    m4_ns(assert_unlock, _) (lock);
}

#endif
