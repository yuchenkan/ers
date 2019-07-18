#ifndef ERI_LIVE_COMMON_H
#define ERI_LIVE_COMMON_H

#include <lib/atomic.h>
#include <lib/printf.h>

struct eri_buf;
struct eri_mtpool;

struct eri_entry;
struct eri_atomic_record;

#define eri_live_in(v)	eri_atomic_load (v, 0)
#define eri_live_out(v)	eri_atomic_fetch_inc (v, 0)

void eri_live_init_get_maps (struct eri_mtpool *pool,
	const struct eri_range *map, struct eri_buf *buf);
void eri_live_init_free_maps (struct eri_mtpool *pool, struct eri_buf *buf);

struct eri_live_atomic;

struct eri_live_atomic *eri_live_create_atomic (
			struct eri_mtpool *pool, uint64_t table_size);
void eri_live_destroy_atomic (struct eri_live_atomic *atomic);

uint64_t eri_live_atomic_get_table_size (struct eri_live_atomic *atomic);

struct eri_pair eri_live_atomic_lock (struct eri_live_atomic *atomic,
				      uint64_t mem, uint8_t size);
struct eri_pair eri_live_atomic_unlock (struct eri_live_atomic *atomic,
					struct eri_pair *idx, uint8_t ok);

struct eri_live_atomic_args
{
  eri_file_t log;
  struct eri_entry *entry;
  uint16_t code;
  void *mem;
  uint8_t size;
  struct eri_atomic_record *rec;
  void *old;
  uint64_t val;
  void *rflags;
};

void eri_live_atomic (struct eri_live_atomic *atomic,
		      struct eri_live_atomic_args *args);

#endif
