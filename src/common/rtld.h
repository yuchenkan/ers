#ifndef ERI_COMMON_RTLD_H
#define ERI_COMMON_RTLD_H

#include <stdint.h>

struct eri_seg;

void eri_map_bin (int32_t fd, struct eri_seg *segs, uint16_t nsegs,
		  uint64_t base, uint64_t page_size);
void eri_map_reloc (struct eri_relative *rels, uint64_t nrels,
		    uint64_t base);

#endif
