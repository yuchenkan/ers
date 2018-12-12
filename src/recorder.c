#include "live.h"

struct eri_live_internal eri_live_internal;

uint8_t
eri_live_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
		  uint64_t a3, uint64_t a4, uint64_t a5,
		  struct eri_live_syscall_info *info,
		  struct eri_live_thread *th)
{
  return eri_live_do_syscall (a0, a1, a2, a3, a4, a5, info);
}

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
