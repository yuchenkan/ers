#ifndef ERI_LIB_MALLOC_H
#define ERI_LIB_MALLOC_H

#include <stdint.h>

#include "lib/util.h"
#include "lib/rbtree.h"

struct eri_pool
{
  uint8_t *buf;
  uint64_t size;
  uint64_t used;

  void (*cb_malloc) (struct eri_pool *, uint64_t, int32_t, void *, void *);
  void (*cb_free) (struct eri_pool *, void *, int32_t, void *);
  void *cb_data;

  ERI_RBT_TREE_FIELDS (block, struct block)
};

int32_t eri_init_pool (struct eri_pool *pool, uint8_t *buf, uint64_t size);
int32_t eri_fini_pool (struct eri_pool *pool);

int32_t eri_malloc (struct eri_pool *pool, uint64_t size, void **p);
int32_t eri_free (struct eri_pool *pool, void *p);

#define eri_assert_init_pool(p, b, s) \
  eri_assert (eri_init_pool (p, b, s) == 0)
#define eri_assert_fini_pool(p) \
  eri_assert (eri_fini_pool (p) == 0)

#define eri_assert_malloc(p, s) \
  ({								\
    void *_p1;							\
    eri_assert (eri_malloc (p, s, &_p1) == 0);			\
    _p1;							\
  })
#define eri_assert_calloc(p, s) \
  ({								\
    uint64_t _s2 = s;						\
    void *_p2 = eri_assert_malloc (p, _s2);			\
    eri_memset (_p2, 0, _s2);					\
    _p2;							\
  })
#define eri_assert_free(p, pp) \
  eri_assert (eri_free (p, pp) == 0)

#include "lib/lock.h"

struct eri_mtpool
{
  int32_t lock;
  struct eri_pool pool;
};

int32_t eri_mtmalloc (struct eri_mtpool *pool, uint64_t size, void **p);
int32_t eri_mtfree (struct eri_mtpool *pool, void *p);

#define eri_assert_mtmalloc(mtp, s) \
  ({								\
    void *_p3;							\
    eri_assert (eri_mtmalloc (mtp, s, &_p3) == 0);		\
    _p3;							\
  })

#define eri_assert_mtcalloc(mtp, s) \
  ({								\
    uint64_t _s4 = s;						\
    void *_p4 = eri_assert_mtmalloc (mtp, _s4);			\
    eri_memset (_p4, 0, _s4);					\
    _p4;							\
  })

#define eri_assert_mtfree(mtp, p) \
  eri_assert (eri_mtfree (mtp, p) == 0)

#define eri_assert_cmalloc(mt, mtp, s) \
  (! (mt) ? eri_assert_malloc (&(mtp)->pool, s)			\
	  : eri_assert_mtmalloc (mtp, s))

#define eri_assert_ccalloc(mt, mtp, s) \
  (! (mt) ? eri_assert_calloc (&(mtp)->pool, s)			\
	  : eri_assert_mtcalloc (mtp, s))

#define eri_assert_cfree(mt, mtp, p) \
  do {								\
    if (! (mt)) eri_assert_free (&(mtp)->pool, p);		\
    else eri_assert_mtfree (mtp, p);				\
  } while (0)

#endif
