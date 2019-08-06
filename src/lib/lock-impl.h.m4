/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#ifndef m4_NS(LIB_LOCK_IMPL_H)
#define m4_NS(LIB_LOCK_IMPL_H)

#include <lib/compiler.h>
#include <lib/lock-common.h>
#include <m4_atomic_h>

void m4_ns(assert_lock, _) (eri_lock_t *lock);
void m4_ns(assert_unlock, _) (eri_lock_t *lock);

void m4_ns(assert_rlock, _) (eri_lock_t *lock, int32_t v);
void m4_ns(assert_wlock, _) (eri_lock_t *lock, int32_t v);
void m4_ns(assert_runlock, _) (eri_lock_t *lock);
void m4_ns(assert_wunlock, _) (eri_lock_t *lock);

static eri_unused void
m4_ns(assert_lock) (eri_lock_t *lock)
{
  if (m4_ns(atomic_exchange) ((uint32_t *) lock, 1, 1))
    m4_ns(assert_lock, _) (lock);
}

static eri_unused void
m4_ns(assert_unlock) (eri_lock_t *lock)
{
  if (m4_ns(atomic_dec_fetch (lock, 1)))
    m4_ns(assert_unlock, _) (lock);
}

static eri_unused void
m4_ns(assert_rlock) (eri_lock_t *lock)
{
  int32_t v = m4_ns(atomic_inc_fetch) ((uint32_t *) lock, 1);
  if (v <= 0) m4_ns(assert_rlock, _) (lock, v);
}

static eri_unused void
m4_ns(assert_wlock) (eri_lock_t *lock)
{
  int32_t v = m4_ns(atomic_compare_exchange ((uint32_t *) lock,
					     0, -ERI_INT_MAX, 1));
  if (v) m4_ns(assert_wlock, _) (lock, v);
}

static eri_unused void
m4_ns(assert_runlock) (eri_lock_t *lock)
{
  uint64_t v = m4_ns(atomic_dec_fetch (lock, 1));
  if (v && ! (v & 0xffffffff)) m4_ns(assert_runlock, _) (lock);
}

static eri_unused void
m4_ns(assert_wunlock) (eri_lock_t *lock)
{
  if (m4_ns(atomic_add_fetch (lock, ERI_INT_MAX, 1)))
    m4_ns(assert_wunlock, _) (lock);
}

#endif
