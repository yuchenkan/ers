#ifndef ERI_MALLOC_H
#define ERI_MALLOC_H

#include <stddef.h>

struct pool
{
  char *buf;
  size_t size;

  struct block *root;
  int lock;
};

int eri_init_pool (struct pool *pool, char *buf, size_t size);

int eri_malloc (struct pool *pool, size_t size, void **p);
int eri_free (struct pool *pool, void *p);

#endif
