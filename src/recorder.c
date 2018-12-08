#include "live.h"

struct eri_live_internal eri_live_internal;

void
eri_live_sync_async (uint64_t cnt, struct eri_live_thread *th)
{
}

void
eri_live_restart_sync_async (uint64_t cnt, struct eri_live_thread *th)
{
}

uint64_t
eri_live_atomic_hash_mem (uint64_t mem, struct eri_live_thread *th)
{
  return 0;
}

void
eri_live_atomic_load (uint64_t mem, uint64_t ver, uint64_t val,
		      struct eri_live_thread *th)
{
}

void
eri_live_atomic_stor (uint64_t mem, uint64_t ver,
		      struct eri_live_thread *th)
{
}

void
eri_live_atomic_load_stor (uint64_t mem, uint64_t ver, uint64_t val,
			   struct eri_live_thread *th)
{
}
