#include <lib/util.h>
#include <lib/malloc.h>
#include <lib/rbtree.h>

#define BLK_FREE	0
#define BLK_NOTFREE	1

struct eri_block
{
  struct eri_block *next;
  struct eri_block *prev;
  uint8_t type : 1;

  ERI_RBT_NODE_FIELDS (eri_block, struct eri_block)
};

static inline uint64_t
block_size (struct eri_pool *pool, struct eri_block *b)
{
  return (b->next
	    ? (uint8_t *) b->next : pool->buf + pool->size) - (uint8_t *) b;
}

static uint8_t
less_than (struct eri_pool *pool, struct eri_block *b1, struct eri_block *b2)
{
  uint64_t s1 = block_size (pool, b1);
  uint64_t s2 = block_size (pool, b2);

  if (s1 != s2) return s1 < s2;
  /* Sort reversely, for search.  */
  if (b1->type != b2->type) return b1->type > b2->type;
  return b1 < b2;
}

ERI_DEFINE_RBTREE1 (static, eri_block, struct eri_pool,
		    struct eri_block, less_than)

#define ALIGN(x)	eri_round_up (x, 16)

#define MIN_BLOCK_SIZE	ALIGN (sizeof (struct eri_block))
#define ALLOC_OFFSET \
  ALIGN (__builtin_offsetof (struct eri_block, eri_block_rbt_parent))

int32_t
eri_init_pool (struct eri_pool *pool, uint8_t *buf, uint64_t size)
{
  if ((uint64_t) buf % 16) return 1;

  eri_memset (pool, 0, sizeof *pool);

  pool->buf = buf;
  pool->size = size;

  if (pool->size < MIN_BLOCK_SIZE)
    return 0;

  struct eri_block *b = (struct eri_block *) pool->buf;
  eri_memset (b, 0, sizeof *b);
  eri_block_rbt_insert (pool, b);
  return 0;
}

int32_t
eri_fini_pool (struct eri_pool *pool)
{
  if (pool->used != 0) return 1;

  if (pool->preserve) return 0;

  if (pool->size >= MIN_BLOCK_SIZE)
    {
      struct eri_block *b = (struct eri_block *) pool->buf;
      eri_block_rbt_remove (pool, b);
    }
  eri_assert (! pool->eri_block_rbt_root);
  return 0;
}

int32_t
eri_malloc (struct eri_pool *pool, uint64_t size, void **p)
{
  uint64_t s = eri_max (MIN_BLOCK_SIZE, ALIGN (size + ALLOC_OFFSET));

  struct eri_block k = {
    (struct eri_block *) ((uint8_t *) &k + s), 0, BLK_NOTFREE
  };
  struct eri_block *b = eri_block_rbt_get (pool, &k, ERI_RBT_GTE);

  *p = 0;
  if (! b)
    {
      if (pool->cb_malloc)
	pool->cb_malloc (pool, size, 1, *p, pool->cb_data);
      return 1;
    }

  eri_block_rbt_remove (pool, b);
  b->type = BLK_NOTFREE;
  *p = (uint8_t *) b + ALLOC_OFFSET;

  if (block_size (pool, b) - s >= MIN_BLOCK_SIZE)
    {
      struct eri_block *n = (struct eri_block *) ((uint8_t *) b + s);
      eri_memset (n, 0, sizeof *n);
      n->next = b->next;
      n->prev = b;
      if (b->next) b->next->prev = n;
      b->next = n;
      eri_block_rbt_insert (pool, n);
    }

  pool->used += block_size (pool, b);
  if (pool->cb_malloc)
    pool->cb_malloc (pool, size, 0, *p, pool->cb_data);
  return 0;
}

#if 0
int32_t
eri_calloc (struct eri_pool *pool, uint64_t size, void **p)
{
  int32_t res = eri_malloc (pool, size, p);
  if (res == 0) eri_memset (*p, 0, size);
  return res;
}
#endif

static void
guard (struct eri_pool *pool, void *b, uint64_t s)
{
#ifndef ERI_NO_CHECK
  eri_memset (b, 0xfc, s);
#endif
}

static void
merge (struct eri_pool *pool, struct eri_block *b)
{
  struct eri_block *n = b->next;
  b->next = n->next;
  if (b->next) b->next->prev = b;
  guard (pool, n, sizeof *n);
}

int32_t
eri_free (struct eri_pool *pool, void *p)
{
  eri_assert ((uint8_t *) p >= pool->buf
	      && (uint8_t *) p < pool->buf + pool->size);

  struct eri_block *b = (struct eri_block *) ((uint8_t *) p - ALLOC_OFFSET);
  eri_assert (pool->used >= block_size (pool, b));
  pool->used -= block_size (pool, b);
  if (pool->preserve) return 0;
  guard (pool, (uint8_t *) b + sizeof *b, block_size (pool, b) - sizeof *b);

  b->type = BLK_FREE;

  if (b->next && b->next->type == BLK_FREE)
    {
      eri_block_rbt_remove (pool, b->next);
      merge (pool, b);
    }

  if (b->prev && b->prev->type == BLK_FREE)
    {
      eri_block_rbt_remove (pool, b->prev);
      b = b->prev;
      merge (pool, b);
    }

  eri_block_rbt_insert (pool, b);
  if (pool->cb_free)
    pool->cb_free (pool, p, 0, pool->cb_data);
  return 0;
}

void
eri_preserve (struct eri_pool *pool)
{
  pool->preserve = 1;
}

int32_t
eri_mtmalloc (struct eri_mtpool *pool, uint64_t size, void **p)
{
  int32_t res;
  eri_assert_lock (&pool->lock);
  res = eri_malloc (&pool->pool, size, p);
  eri_assert_unlock (&pool->lock);
  return res;
}

int32_t
eri_mtfree (struct eri_mtpool *pool, void *p)
{
  int32_t res;
  eri_assert_lock (&pool->lock);
  res = eri_free (&pool->pool, p);
  eri_assert_unlock (&pool->lock);
  return res;
}
