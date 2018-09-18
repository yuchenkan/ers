#include "util.h"
#include "malloc.h"

#define BLK_FREE	0
#define BLK_NOTFREE	1

struct block
{
  struct block *next;
  struct block *prev;
  unsigned char type : 1;

  ERI_RBT_NODE_FIELDS (block, struct block)
};

static inline size_t
block_size (struct eri_pool *pool, struct block *b)
{
  return (b->next ? (char *) b->next : pool->buf + pool->size) - (char *) b;
}

static char
less_than (struct eri_pool *pool, struct block *b1, struct block *b2)
{
  size_t s1 = block_size (pool, b1);
  size_t s2 = block_size (pool, b2);

  if (s1 != s2) return s1 < s2;
  if (b1->type != b2->type) return b1->type > b2->type; // sort reversely, for search
  return b1 < b2;
}

#include "rbtree.h"
ERI_DEFINE_RBTREE1 (static, block, struct eri_pool, struct block, less_than)

#define ALIGN(x) eri_round_up (x, 16)

#define MIN_BLOCK_SIZE ALIGN (sizeof (struct block))
#define ALLOC_OFFSET ALIGN (__builtin_offsetof (struct block, block_rbt_parent))

int
eri_init_pool (struct eri_pool *pool, char *buf, size_t size)
{
  eri_memset (pool, 0, sizeof *pool);

  pool->buf = buf;
  pool->size = size;

  if (pool->size < MIN_BLOCK_SIZE)
    return 0;

  struct block *b = (struct block *) pool->buf;
  eri_memset (b, 0, sizeof *b);
  block_rbt_insert (pool, b);
  return 0;
}

int
eri_fini_pool (struct eri_pool *pool)
{
  eri_assert (pool->used == 0);
  if (pool->size >= MIN_BLOCK_SIZE)
    {
      struct block *b = (struct block *) pool->buf;
      block_rbt_remove (pool, b);
    }
  eri_assert (! pool->block_rbt_root);
  pool->size = 0;
  pool->buf = 0;
  return 0;
}

int
eri_malloc (struct eri_pool *pool, size_t size, void **p)
{
  size_t s = eri_max (MIN_BLOCK_SIZE, ALIGN (size + ALLOC_OFFSET));

  struct block k = { (struct block *) ((char *) &k + s), NULL, BLK_NOTFREE };
  struct block *b = block_rbt_get (pool, &k, ERI_RBT_GT);

  *p = NULL;
  if (! b)
    {
      if (pool->cb_malloc)
	pool->cb_malloc (pool, size, 1, *p, pool->cb_data);
      return 1;
    }

  block_rbt_remove (pool, b);
  b->type = BLK_NOTFREE;
  *p = (char *) b + ALLOC_OFFSET;

  if (block_size (pool, b) - s >= MIN_BLOCK_SIZE)
    {
      struct block *n = (struct block *) ((char *) b + s);
      eri_memset (n, 0, sizeof *n);
      n->next = b->next;
      n->prev = b;
      if (b->next) b->next->prev = n;
      b->next = n;
      block_rbt_insert (pool, n);
    }

  pool->used += block_size (pool, b);
  if (pool->cb_malloc)
    pool->cb_malloc (pool, size, 0, *p, pool->cb_data);
  return 0;
}

int
eri_calloc (struct eri_pool *pool, size_t size, void **p)
{
  int res = eri_malloc (pool, size, p);
  if (res == 0) eri_memset (*p, 0, size);
  return res;
}

static void
merge (struct block *b)
{
  struct block *n = b->next;
  b->next = n->next;
  if (b->next) b->next->prev = b;
  eri_memset (n, 0xfc, sizeof *n); /* XXX safety check */
}

int
eri_free (struct eri_pool *pool, void *p)
{
  eri_assert ((char *) p >= pool->buf && (char *) p < pool->buf + pool->size);

  struct block *b = (struct block *) ((char *) p - ALLOC_OFFSET);
  eri_memset ((char *) b + sizeof *b, 0xfc, block_size (pool, b) - sizeof *b); /* XXX safety check */

  eri_assert (pool->used >= block_size (pool, b));
  pool->used -= block_size (pool, b);
  b->type = BLK_FREE;

  if (b->next && b->next->type == BLK_FREE)
    {
      block_rbt_remove (pool, b->next);
      merge (b);
    }

  if (b->prev && b->prev->type == BLK_FREE)
    {
      block_rbt_remove (pool, b->prev);
      b = b->prev;
      merge (b);
    }

  block_rbt_insert (pool, b);
  if (pool->cb_free)
    pool->cb_free (pool, p, 0, pool->cb_data);
  return 0;
}
