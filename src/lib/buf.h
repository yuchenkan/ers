#ifndef ERI_LIB_BUF_H
#define ERI_LIB_BUF_H

#include <stdint.h>

#include "lib/malloc.h"

typedef int32_t (*eri_buf_alloc_t) (void *, uint64_t, void **);
typedef int32_t (*eri_buf_free_t) (void *, void *);

struct eri_buf
{
  eri_buf_alloc_t alloc;
  eri_buf_free_t free;
  void *data;

  uint64_t size;
  void *buf;
  uint64_t off;
};

int32_t eri_buf_init (struct eri_buf *buf, eri_buf_alloc_t alloc,
		      eri_buf_free_t free, void *data, uint64_t size);
int32_t eri_buf_fini (struct eri_buf *buf);

int32_t eri_buf_reserve (struct eri_buf *buf, uint64_t size);
int32_t eri_buf_append (struct eri_buf *buf, const void *data, uint64_t size);
int32_t eri_buf_concat (struct eri_buf *buf, const struct eri_buf *data);

#define eri_buf_static_init(buf, data, size) \
  eri_buf_init (buf, 0, 0, data, size)
#define eri_buf_pool_init(buf, pool, size) \
  eri_buf_init (buf, (eri_buf_alloc_t) eri_malloc,			\
		(eri_buf_free_t) eri_free, pool, size)
#define eri_buf_mtpool_init(buf, mtpool, size) \
  eri_buf_init (buf, (eri_buf_alloc_t) eri_mtmalloc,			\
		(eri_buf_free_t) eri_mtfree, mtpool, size)

#endif
