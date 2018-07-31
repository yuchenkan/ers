#include "util.h"
#include "lock.h"
#include "malloc.h"

#define BLK_FREE	0
#define BLK_NOTFREE	1

#define BLK_RED		0
#define BLK_BLACK	1

struct block
{
  struct block *next;
  struct block *prev;
  unsigned char type : 1;
  unsigned char color : 1;

  struct block *parent;
  struct block *left;
  struct block *right;
};

static size_t
block_size (struct pool *pool, struct block *n)
{
  return (n->next ? (char *) n->next : pool->buf + pool->size) - (char *) n;
}

static char
less_than (struct pool *pool, struct block *n1, struct block *n2)
{
  size_t s1 = block_size (pool, n1);
  size_t s2 = block_size (pool, n2);

  if (s1 != s2) return s1 < s2;
  if (n1->type != n2->type) return n1->type > n2->type; // sort reversely, for search
  return n1 < n2;
}

static int
check_recurse (struct pool *pool, struct block *n, struct block **v)
{
  if (! n) return 0;

  if (n->color == BLK_RED)
    {
      eri_assert (! n->left || n->left->color == BLK_BLACK);
      eri_assert (! n->right || n->right->color == BLK_BLACK);
    }

  int h = check_recurse (pool, n->left, v);
  eri_assert (! *v || less_than (pool, *v, n));
  v = &n;
  eri_assert (h == check_recurse (pool, n->right, v));
  eri_assert (*v == n || less_than (pool, n, *v));

  return h + (n->color == BLK_BLACK);
}

static void
check (struct pool *pool)
{
  if (pool->root) eri_assert (pool->root->color == BLK_BLACK);

  struct block *v = NULL;
  check_recurse (pool, pool->root, &v);
}


static struct block *
parent (struct block *n)
{
  return n->parent;
}

static struct block *
grandparent (struct block *n)
{
  return parent (n) ? parent (parent (n)) : NULL;
}

static struct block *
sibling (struct block *n)
{
  struct block *p = parent (n);
  if (! p) return NULL;
  return n == p->left ? p->right : p->left;
}

struct block *
uncle (struct block *n)
{
 return grandparent (n) ? sibling (parent (n)) : NULL;
}

static void
rotate_left (struct pool *pool, struct block *n)
{
  struct block *p = parent (n);
  struct block *nn = n->right;
  n->right = nn->left;

  if (nn->left) nn->left->parent = n;
  nn->parent = p;

  if (! p) pool->root = nn;
  else if (n == p->left) p->left = nn;
  else p->right = nn;

  nn->left = n;
  n->parent = nn;
}

static void
rotate_right (struct pool *pool, struct block *n)
{
  struct block *p = parent (n);
  struct block *nn = n->left;
  n->left = nn->right;

  if (nn->right) nn->right->parent = n;
  nn->parent = p;

  if (! p) pool->root = nn;
  else if (n == p->right) p->right = nn;
  else p->left = nn;

  nn->right = n;
  n->parent = nn;
}

static void
insert_recurse (struct pool *pool, struct block *r, struct block *n)
{
  if (less_than (pool, n, r))
    {
      if (r->left) insert_recurse (pool, r->left, n);
      else
        {
          r->left = n;
          n->parent = r;
        }
    }
  else if (less_than (pool, r, n))
    {
      if (r->right) insert_recurse (pool, r->right, n);
      else
        {
          r->right = n;
          n->parent = r;
        }
    }
  else eri_assert (0);
}

static void
insert_repair (struct pool *pool, struct block *n)
{
  if (! parent (n)) n->color = BLK_BLACK;
  else if (parent (n)->color == BLK_RED)
    {
      if (uncle (n)->color == BLK_RED)
	{
	  parent (n)->color = BLK_BLACK;
	  uncle (n)->color = BLK_BLACK;
	  grandparent (n)->color = BLK_RED;
	  insert_repair (pool, grandparent (n));
	}
      else
	{
	  struct block *p = parent (n);
	  struct block *g = grandparent (n);

	  if (p == g->left)
	    {
	      if (n == p->right)
		{
		  rotate_left (NULL, p);
		  n = n->left;
		}
	      rotate_right (pool, g);
	    }
	  else
	    {
	      if (n == p->left)
		{
 		  rotate_right (NULL, p);
		  n = n->right; 
		}
	      rotate_left (pool, g);
	    }
	  parent (n)->color = BLK_BLACK;
	  g->color = BLK_RED;
	}
    }
}

static void
insert (struct pool *pool, struct block *n)
{
  n->color = BLK_RED;
  n->parent = n->left = n->right = NULL;

  if (! pool->root) pool->root = n;
  else insert_recurse (pool, pool->root, n);

  insert_repair (pool, n);

  check (pool);
}

static void
remove_repair (struct pool *pool, struct block *p, struct block *n)
{
  if (! p) return;

  struct block *s = n == p->left ? p->right : p->left;
  if (s->color == BLK_RED)
    {
      p->color = BLK_RED;
      s->color = BLK_BLACK;
      if (n == p->left)
	rotate_left (pool, p);
      else
	rotate_right (pool, p);
      s = n == p->left ? p->right : p->left;
    }

  if ((! s->left || s->left->color == BLK_BLACK)
      && (! s->right || s->right->color == BLK_BLACK))
    {
      s->color = BLK_RED;
      if (p->color == BLK_BLACK)
	remove_repair (pool, parent (p), p);
      else
	p->color = BLK_BLACK;
    }
  else
    {
      if (n == p->left
	  && (s->left && s->left->color == BLK_RED)
	  && (! s->right || s->right->color == BLK_BLACK))
	{
	  s->color = BLK_RED;
	  s->left->color = BLK_BLACK;
	  rotate_right (NULL, s);
	  s = p->right;
	}
      else if (n == p->right
	       && (! s->left || s->left->color == BLK_BLACK)
	       && (s->right && s->right->color == BLK_RED))
	{
	  s->color = BLK_RED;
	  s->right->color = BLK_BLACK;
	  rotate_left (NULL, s);
	  s = p->left;
	}

      s->color = p->color;
      p->color = BLK_BLACK;

      if (n == p->left)
	{
	  s->right->color = BLK_BLACK;
	  rotate_left (pool, p);
	}
      else
	{
	  s->left->color = BLK_BLACK;
	  rotate_right (pool, p);
	}
    }
}

static void
remove_one_child (struct pool *pool, struct block *n)
{
  struct block *c = ! n->right ? n->left : n->right;

  if (c) c->parent = parent (n);
  if (! parent (n)) pool->root = c;
  else if (n == parent (n)->left) parent (n)->left = c;
  else parent (n)->right = c;

  if (n->color == BLK_BLACK)
    {
      if (c && c->color == BLK_RED)
	c->color = BLK_BLACK;
      else
	remove_repair (pool, parent (n), c);
    }
}

static void
remove (struct pool *pool, struct block *n)
{
  if (n->left && n->right)
    {
      struct block *m = n->left;
      while (m->right) m = m->right;
      remove_one_child (pool, m);

      m->parent = parent (n);
      m->left = n->left;
      m->right = n->right;
      m->color = n->color;

      if (! parent (m)) pool->root = m;
      else if (m == parent (m)->left) parent (m)->left = m;
      else parent (m)->right = m;

      if (m->left) m->left->parent = m;
      if (m->right) m->right->parent = m;
    }
  else remove_one_child (pool, n);

  check (pool);
}

static struct block *
get_first_greater_than (struct pool *pool, struct block *n)
{
  struct block *r = pool->root;
  struct block *v = NULL;
  while (r)
    {
      if (less_than (pool, r, n)) r = r->right;
      else
	{
	  v = r;
	  r = r->left;
	}
    }
  return v;
}

#define ALIGN(x) ALIGN_MASK (x, (typeof (x)) 15)
#define ALIGN_MASK(x, mask) (((x) + (mask)) & ~(mask))

#define MIN_BLOCK_SIZE ALIGN (sizeof (struct block))
#define ALLOC_OFFSET __builtin_offsetof (struct block, parent)

int
eri_init_pool (struct pool *pool, char *buf, size_t size)
{
  pool->buf = buf;
  pool->size = size;
  pool->root = NULL;
  pool->lock = 0;

  if (pool->size < MIN_BLOCK_SIZE)
    return 0;

  struct block *b = (struct block *) pool->buf;
  eri_memset (b, 0, sizeof *b);
  insert (pool, b);
  return 0;
}

int
eri_malloc (struct pool *pool, size_t size, void **p)
{
  eri_lock (&pool->lock);

  size_t s = eri_max (MIN_BLOCK_SIZE, ALIGN (size + ALLOC_OFFSET));

  struct block k = { (struct block *) ((char *) &k + s), NULL, BLK_NOTFREE };
  struct block *b = get_first_greater_than (pool, &k);

  *p = NULL;
  if (! b) return 1;

  remove (pool, b);
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
      insert (pool, n);
    }

  eri_unlock (&pool->lock);
  return 0;
}

static void
merge (struct block *b)
{
  b->next = b->next->next;
  if (b->next) b->next->prev = b;
}

int
eri_free (struct pool *pool, void *p)
{
  eri_lock (&pool->lock);

  struct block *b = (struct block *) ((char *) p - ALLOC_OFFSET);
  b->type = BLK_FREE;

  if (b->next && b->next->type == BLK_FREE)
    {
      remove (pool, b->next);
      merge (b);
    }

  if (b->prev && b->prev->type == BLK_FREE)
    {
      remove (pool, b->prev);
      b = b->prev;
      merge (b);
    }

  insert (pool, b);
  eri_unlock (&pool->lock);
  return 0;
}
