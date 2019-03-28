#ifndef ERI_LIB_LOCK_H
#define ERI_LIB_LOCK_H

#include <stdint.h>

struct eri_lock
{
  uint32_t wait;
  uint32_t lock;
};

#define ERI_INIT_LOCK(locked)	{ 0, locked }
#define eri_init_lock(l, locked) \
  do { struct eri_lock *_l = l;						\
       _l->wait = 0; _l->lock = locked; } while (0)

void eri_assert_lock (struct eri_lock *lock);
void eri_assert_unlock (struct eri_lock *lock);

#endif
