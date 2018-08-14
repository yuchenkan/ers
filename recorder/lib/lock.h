#ifndef ERI_LOCK_H
#define ERI_LOCK_H

struct eri_lock
{
  int lock;
  int fd;
};

#define eri_init_lock (lock, fd) \
  do { struct eri_lock *_l = lock; _l->lock = 0; _l->fd = fd; } while (0)
void eri_lock (char replay, unsigned long tid, struct eri_lock *lock);
void eri_unlock (struct eri_lock *lock);

#define ERI_ATOMIC_TYPE(type) \
  struct { struct eri_lock lock; type val; }

#define eri_init_atomic(atomic, fd) eri_init_lock (&(atomic)->lock)

#define ERI_ATOMIC_FETCH_ADD(r, t, m, v) \
  ({							\
    char __r = r;					\
    unsigned long __t = t;				\
    typeof (m) __m = m;					\
    typeof (v) __v = v;					\
    eri_lock (__r, __t, &__m->lock);			\
    typeof (__m->val) __o = __m->val;			\
    __m->val += __v;					\
    eri_unlock (&__m->lock);				\
    __o;						\
  })

#define ERI_ATOMIC_FETCH_SUB(r, t, m, v) \
  ERI_ATOMIC_FETCH_ADD (r, t, m, -(v))
#define ERI_ATOMIC_ADD_FETCH(r, t, m, v) \
  ({ typeof (v) _v = (v); ERI_ATOMIC_FETCH_ADD (r, t, m, _v) + _v; })
#define ERI_ATOMIC_SUB_FETCH(r, t, m, v) \
  ({ typeof (v) _v = (v); ERI_ATOMIC_FETCH_SUB (r, t, m, _v) - _v; })

#define ERI_ATOMIC_COMPARE_EXCHANGE(r, t, m, e, v) \
  ({							\
    char __r = r;					\
    unsigned long __t = t;				\
    typeof (m) __m = m;					\
    typeof (e) __e = e;					\
    typeof (v) __v = v;					\
    eri_lock (__r, __t, &__m->lock);			\
    char __ex = __m->val == __e;			\
    if (__ex) __m->val = __v;				\
    eri_unlock (&__m->lock);				\
    __ex;						\
  })

#endif
