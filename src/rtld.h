#ifndef ERI_RTLD_H
#define ERI_RTLD_H

#include <stdint.h>

struct eri_seg;

void eri_map_bin (int32_t fd, struct eri_seg *segs, uint16_t nsegs,
		  uint64_t base, uint64_t page_size);

#endif
