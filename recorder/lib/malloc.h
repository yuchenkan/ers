#ifndef ERS_MALLOC_H
#define ERS_MALLOC_H

#include <stddef.h>

#include "rbtree.h"

struct ers_pool
{
  char *buf;
  size_t size;
  size_t used;

  ERS_RBT_TREE_FIELDS (block, struct block)
  int lock;
};

int ers_init_pool (struct ers_pool *pool, char *buf, size_t size);

int ers_malloc (struct ers_pool *pool, size_t size, void **p);
int ers_calloc (struct ers_pool *pool, size_t size, void **p);
int ers_free (struct ers_pool *pool, void *p);

#endif
