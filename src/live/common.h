#ifndef ERI_LIVE_COMMON_H
#define ERI_LIVE_COMMON_H

#include <lib/atomic.h>
#include <lib/syscall.h>

#define eri_live_in(v)	eri_atomic_load (v, 0)
#define eri_live_out(v)	eri_atomic_fetch_inc (v, 0)

#endif
