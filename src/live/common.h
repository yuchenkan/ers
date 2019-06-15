#ifndef ERI_LIVE_COMMON_H
#define ERI_LIVE_COMMON_H

#include <lib/atomic.h>

struct eri_buf;
struct eri_mtpool;

#define eri_live_in(v)	eri_atomic_load (v, 0)
#define eri_live_out(v)	eri_atomic_fetch_inc (v, 0)

void eri_live_init_get_maps (struct eri_mtpool *pool,
	const struct eri_range *map, struct eri_buf *buf);
void eri_live_init_free_maps (struct eri_mtpool *pool, struct eri_buf *buf);

#endif
