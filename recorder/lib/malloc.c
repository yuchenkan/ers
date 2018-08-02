#include "util.h"
#include "lock.h"
#include "malloc.h"

#define BLK_FREE	0
#define BLK_NOTFREE	1

struct block
{
  struct block *next;
  struct block *prev;
  unsigned char type : 1;

  ERS_RBT_NODE_FIELDS (struct block)
};

static inline size_t
block_size (struct ers_pool *pool, struct block *n)
{
  return (n->next ? (char *) n->next : pool->buf + pool->size) - (char *) n;
}

static char
less_than (struct ers_pool *pool, struct block *n1, struct block *n2)
{
  size_t s1 = block_size (pool, n1);
  size_t s2 = block_size (pool, n2);

  if (s1 != s2) return s1 < s2;
  if (n1->type != n2->type) return n1->type > n2->type; // sort reversely, for search
  return n1 < n2;
}

#include "rbtree.h"
ERS_DEFINE_RBTREE1 (static, block, struct ers_pool, struct block, less_than)

#define ALIGN(x) ALIGN_MASK (x, (typeof (x)) 15)
#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))

#define MIN_BLOCK_SIZE ALIGN (sizeof (struct block))
#define ALLOC_OFFSET __builtin_offsetof (struct block, parent)

int
ers_init_pool (struct ers_pool *pool, char *buf, size_t size)
{
  pool->buf = buf;
  pool->size = size;
  pool->used = 0;
  ERS_RBT_INIT_TREE (pool);
  pool->root = NULL;
  pool->lock = 0;

  if (pool->size < MIN_BLOCK_SIZE)
    return 0;

  struct block *b = (struct block *) pool->buf;
  ers_memset (b, 0, sizeof *b);
  block_insert (pool, b);
  return 0;
}

int
ers_malloc (struct ers_pool *pool, size_t size, void **p)
{
  ers_lock (&pool->lock);

  size_t s = ers_max (MIN_BLOCK_SIZE, ALIGN (size + ALLOC_OFFSET));

  struct block k = { (struct block *) ((char *) &k + s), NULL, BLK_NOTFREE };
  struct block *b = block_get (pool, &k, ERS_RBT_GT);

  *p = NULL;
  if (! b) return 1;

  pool->used += s;

  block_remove (pool, b);
  b->type = BLK_NOTFREE;
  *p = (char *) b + ALLOC_OFFSET;

  if (block_size (pool, b) - s >= MIN_BLOCK_SIZE)
    {
      struct block *n = (struct block *) ((char *) b + s);
      ers_memset (n, 0, sizeof *n);
      n->next = b->next;
      n->prev = b;
      if (b->next) b->next->prev = n;
      b->next = n;
      block_insert (pool, n);
    }

  ers_unlock (&pool->lock);
  return 0;
}

int
ers_calloc (struct ers_pool *pool, size_t size, void **p)
{
  int res = ers_malloc (pool, size, p);
  if (res == 0) ers_memset (*p, 0, size);
  return res;
}

static void
merge (struct block *b)
{
  b->next = b->next->next;
  if (b->next) b->next->prev = b;
}

int
ers_free (struct ers_pool *pool, void *p)
{
  ers_lock (&pool->lock);

  struct block *b = (struct block *) ((char *) p - ALLOC_OFFSET);

  pool->used -= block_size (pool, b);
  ers_assert (pool->used >= 0);
  b->type = BLK_FREE;

  if (b->next && b->next->type == BLK_FREE)
    {
      block_remove (pool, b->next);
      merge (b);
    }

  if (b->prev && b->prev->type == BLK_FREE)
    {
      block_remove (pool, b->prev);
      b = b->prev;
      merge (b);
    }

  block_insert (pool, b);
  ers_unlock (&pool->lock);
  return 0;
}
