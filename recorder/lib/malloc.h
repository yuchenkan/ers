#ifndef ERI_MALLOC_H
#define ERI_MALLOC_H

#include <stddef.h>

#include "rbtree.h"

struct eri_pool
{
  char *buf;
  size_t size;
  size_t used;

  ERI_RBT_TREE_FIELDS (block, struct block)
};

int eri_init_pool (struct eri_pool *pool, char *buf, size_t size);
int eri_fini_pool (struct eri_pool *pool);

int eri_malloc (struct eri_pool *pool, size_t size, void **p);
int eri_free (struct eri_pool *pool, void *p);

#endif
