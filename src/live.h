#ifndef ERI_LIVE_H
#define ERI_LIVE_H

#include <stdint.h>

#include "live-entry.h"
#include "lib/syscall.h"

void eri_live_start_sigaction (int32_t sig,
		struct eri_live_entry_sigaction_info *info, void *thread);

#endif
