#ifndef ERI_LIB_LOCK_H
#define ERI_LIB_LOCK_H

void eri_lock (int32_t *lock);
void eri_unlock (int32_t *lock);

#define eri_clock(mt, lock) \
  do { if (mt) eri_lock (lock); } while (0)
#define eri_cunlock(mt, lock) \
  do { if (mt) eri_unlock (lock); } while (0)

#endif
