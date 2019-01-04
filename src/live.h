#ifndef ERI_LIVE_H
#define ERI_LIVE_H

#include <stdint.h>

#include "rtld.h"
#include "common.h"
#include "live-entry.h"
#include "lib/syscall.h"

void eri_live_init (struct eri_common *common,
		    struct eri_rtld *rtld) __attribute__ ((noreturn));

void eri_live_get_sig_action (int32_t sig, struct eri_siginfo *info,
			      struct eri_ucontext *ctx, int32_t intr,
			      struct eri_live_entry_sig_action_info *act_info,
			      void *thread);
uint64_t eri_live_get_sig_stack (struct eri_live_entry_sig_stack_info *info,
				 void *thread);

void eri_live_start_thread (void *thread);
int8_t eri_live_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
			 uint64_t a3, uint64_t a4, uint64_t a5,
			 uint64_t *rax, void *thread);

void eri_live_sync_async (uint64_t cnt, void *thread);
void eri_live_restart_sync_async (uint64_t cnt, void *thread);

uint64_t eri_live_atomic_hash_mem (uint64_t mem, void *thread);
void eri_live_atomic_load (uint64_t mem, uint64_t ver, uint64_t val,
			   void *thread);
void eri_live_atomic_store (uint64_t mem, uint64_t ver, void *thread);
void eri_live_atomic_load_store (uint64_t mem, uint64_t ver, uint64_t val,
				 void *thread);
#endif
