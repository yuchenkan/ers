#ifndef ERI_LIVE_H
#define ERI_LIVE_H

#include <stdint.h>

#include "rtld.h"
#include "common.h"
#include "live-entry.h"
#include "lib/syscall.h"

void eri_live_init (struct eri_common *common,
		    struct eri_rtld *rtld) __attribute__ ((noreturn));

void eri_live_start_sigaction (int32_t sig, struct eri_stack *stack,
		struct eri_live_entry_sigaction_info *info, void *thread);

int8_t eri_live_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
			 uint64_t a3, uint64_t a4, uint64_t a5,
			 struct eri_live_entry_syscall_info *info,
			 void *thread);

void eri_live_sync_async (uint64_t cnt, void *thread);
void eri_live_restart_sync_async (uint64_t cnt, void *thread);

uint64_t eri_live_atomic_hash_mem (uint64_t mem, void *thread);
void eri_live_atomic_load (uint64_t mem, uint64_t ver, uint64_t val,
			   void *thread);
void eri_live_atomic_store (uint64_t mem, uint64_t ver, void *thread);
void eri_live_atomic_load_store (uint64_t mem, uint64_t ver, uint64_t val,
				 void *thread);
#endif
