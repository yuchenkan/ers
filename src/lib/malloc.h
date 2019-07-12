#ifndef ERI_LIB_MALLOC_H
#define ERI_LIB_MALLOC_H

#include <stdint.h>

#include <lib/util.h>
#include <lib/rbtree.h>

struct eri_block;

struct eri_pool
{
  uint8_t *buf;
  uint64_t size;
  uint64_t used;

  uint8_t preserve;

  void (*cb_malloc) (struct eri_pool *, uint64_t, int32_t, void *, void *);
  void (*cb_free) (struct eri_pool *, void *, int32_t, void *);
  void *cb_data;

  ERI_RBT_TREE_FIELDS (eri_block, struct eri_block)
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
  ({									\
    void *_p1;								\
    eri_assert (eri_malloc (p, s, &_p1) == 0);				\
    _p1;								\
  })
#define eri_assert_calloc(p, s) \
  ({									\
    uint64_t _s2 = s;							\
    void *_p2 = eri_assert_malloc (p, _s2);				\
    eri_memset (_p2, 0, _s2);						\
    _p2;								\
  })
#define eri_assert_free(p, pp)		eri_assert (eri_free (p, pp) == 0)

void eri_preserve (struct eri_pool *pool);

#include <lib/lock.h>

struct eri_mtpool
{
  eri_lock_t lock;
  struct eri_pool pool;
};

int32_t eri_mtmalloc (struct eri_mtpool *pool, uint64_t size, void **p);
int32_t eri_mtfree (struct eri_mtpool *pool, void *p);

#define eri_assert_init_mtpool(mtp, b, s) \
  do {									\
    struct eri_mtpool *_mtp = mtp;					\
    _mtp->lock = 0;							\
    eri_assert_init_pool (&_mtp->pool, b, s);				\
  } while (0)

#define eri_assert_fini_mtpool(mtp) \
  eri_assert_fini_pool (&(mtp)->pool)

#define eri_assert_mtmalloc(mtp, s) \
  ({									\
    void *_p3;								\
    eri_assert (eri_mtmalloc (mtp, s, &_p3) == 0);			\
    _p3;								\
  })

#define eri_assert_mtcalloc(mtp, s) \
  ({									\
    uint64_t _s4 = s;							\
    void *_p4 = eri_assert_mtmalloc (mtp, _s4);				\
    eri_memset (_p4, 0, _s4);						\
    _p4;								\
  })

#define eri_assert_mtfree(mtp, p)	eri_assert (eri_mtfree (mtp, p) == 0)

struct _eri_field_size
{
  uint64_t offset;
  uint64_t size;
};

static eri_unused void *
_eri_assert_mtmalloc_struct (struct eri_mtpool *pool, uint64_t type_size,
			     struct _eri_field_size *sizes, uint64_t n)
{
  uint64_t i, sum = n != 0 ? eri_round_up (type_size, 16) : type_size;
  for (i = 0; i < n; ++i)
    sum += i != n - 1 ? eri_round_up (sizes[i].size, 16) : sizes[i].size;
  uint8_t *p = eri_assert_mtmalloc (pool, sum);
  sum = eri_round_up (type_size, 16);
  for (i = 0; i < n; ++i)
    {
      *(void **) (p + sizes[i].offset) = p + sum;
      sum += eri_round_up (sizes[i].size, 16);
    }
  return p;
}

#define __ERI_MALLOC_FIELD_SIZE(t, f, s) \
  { __builtin_offsetof (t, f), s },

#define _ERI_MALLOC_FIELD_SIZE(i, fs, t) \
  ERI_EVAL1 (__ERI_MALLOC_FIELD_SIZE ERI_PP_CONCAT1 ((t), fs))

#define eri_assert_mtmalloc_struct(mtp, t, ...) \
  ({									\
    struct _eri_field_size _sizes[] = {					\
      ERI_PP_FOREACH (_ERI_MALLOC_FIELD_SIZE, (t), ##__VA_ARGS__)	\
    };									\
    (t *) _eri_assert_mtmalloc_struct (mtp, sizeof (t), _sizes,		\
				       eri_length_of (_sizes));		\
  })

#endif
