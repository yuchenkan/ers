#ifndef ERI_RTLD_H
#define ERI_RTLD_H

#include <stdint.h>

struct eri_seg;

typedef uint64_t (*eri_map_bin_base_t) (struct eri_seg *, uint16_t,
					uint64_t, void *);
uint64_t eri_map_bin (const char *path, uint64_t page_size,
		      eri_map_bin_base_t map_base, void *args);

#endif
