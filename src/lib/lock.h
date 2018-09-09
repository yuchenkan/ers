#ifndef ERI_LOCK_H
#define ERI_LOCK_H

void eri_lock (int *lock, char futex);
void eri_unlock (int *lock, char futex);

#endif
