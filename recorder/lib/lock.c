void
ers_lock (int *lock)
{
  while (__atomic_exchange_n (lock, 1, __ATOMIC_ACQUIRE))
    continue;
}

void
ers_unlock (int *lock)
{
  __atomic_store_n (lock, 0, __ATOMIC_RELEASE);
}
