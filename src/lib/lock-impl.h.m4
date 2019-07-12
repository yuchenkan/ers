/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#ifndef m4_NS(LIB_LOCK_IMPL_H)
#define m4_NS(LIB_LOCK_IMPL_H)

#include <lib/compiler.h>
#include <lib/lock-common.h>
#include <m4_atomic_h>

void m4_ns(assert_lock, _) (eri_lock_t *lock);

static eri_unused void
m4_ns(assert_lock) (eri_lock_t *lock)
{
  if (! m4_ns(atomic_exchange) ((uint32_t *) lock, 1, 1)) return;
  m4_ns(assert_lock, _) (lock);
}

void m4_ns(assert_unlock, _) (eri_lock_t *lock);

static eri_unused void
m4_ns(assert_unlock) (eri_lock_t *lock)
{
  if (m4_ns(atomic_dec_fetch (lock, 1)))
    m4_ns(assert_unlock, _) (lock);
}

#endif
