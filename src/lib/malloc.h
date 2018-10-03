#ifndef ERI_MALLOC_H
#define ERI_MALLOC_H

#include <stddef.h>

#include "rbtree.h"

struct eri_pool
{
  char *buf;
  size_t size;
  size_t used;

  void (*cb_malloc) (struct eri_pool *, size_t, int, void *, void *);
  void (*cb_free) (struct eri_pool *, void *, int, void *);
  void *cb_data;

  ERI_RBT_TREE_FIELDS (block, struct block)
};

int eri_init_pool (struct eri_pool *pool, char *buf, size_t size);
int eri_fini_pool (struct eri_pool *pool);

int eri_malloc (struct eri_pool *pool, size_t size, void **p);
int eri_free (struct eri_pool *pool, void *p);

#include "lock.h"
#include "util.h"

struct eri_mtpool
{
  int lock;
  struct eri_pool pool;
};

int eri_mtmalloc (struct eri_mtpool *pool, size_t size, void **p);
int eri_mtfree (struct eri_mtpool *pool, void *p);

#define eri_assert_mtmalloc(mtp, s) \
  ({								\
    void *__p1;							\
    eri_assert (eri_mtmalloc (mtp, s, &__p1) == 0);		\
    __p1;							\
  })

#define eri_assert_mtcalloc(mtp, s) \
  ({								\
    size_t __s2 = s;						\
    void *__p2 = eri_assert_mtmalloc (mtp, __s2);		\
    eri_memset (__p2, 0, __s2);					\
    __p2;							\
  })

#define eri_assert_mtfree(mtp, p) \
  do { eri_assert (eri_mtfree (mtp, p) == 0); } while (0)

#endif
