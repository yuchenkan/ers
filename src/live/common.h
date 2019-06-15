#ifndef ERI_LIVE_COMMON_H
#define ERI_LIVE_COMMON_H

#include <lib/atomic.h>

struct eri_mtpool;
struct eri_smaps_map;

#define eri_live_in(v)	eri_atomic_load (v, 0)
#define eri_live_out(v)	eri_atomic_fetch_inc (v, 0)

void eri_live_init_foreach_map (
	struct eri_mtpool *pool, const struct eri_range *map,
	void (*proc) (const struct eri_smaps_map *, void *), void *args);

#endif
