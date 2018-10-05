#ifndef ERI_RBTREE_H
#define ERI_RBTREE_H

#include "util.h"

/* tree_type { ERI_RBT_TREE_FIELDS (pfx, node_type) ... };
   node_type { key_type key; ERI_RBT_NODE_FIELDS (pfx, node_type) ... };
   int less_than (tree_type *tree, key_type *k1, key_type *k2);

   Zero out the ERI_RBT_TREE_FIELDS or call ERI_RBT_INIT_TREE before use.

   The key has to be the first field or the node to allow casting.
   The order of all other fields are irrelevant.

   Bit fileds of ERI_RBT_NODE_FIELDS are at the beginning. */

#define ERI_RBT_INIT_TREE(pfx, tree) \
  do {						\
    typeof (tree) __tree = tree;		\
    __tree->pfx##_rbt_root = 0;			\
    __tree->pfx##_rbt_size = 0;			\
   } while (0)
#define ERI_RBT_TREE_FIELDS(pfx, node_type) node_type *pfx##_rbt_root; size_t pfx##_rbt_size;
#define ERI_RBT_NODE_FIELDS(pfx, node_type) \
  unsigned char pfx##_rbt_color : 1; node_type *pfx##_rbt_parent, *pfx##_rbt_left, *pfx##_rbt_right;

#define ERI_RBT_EQ	1
#define ERI_RBT_LT	2
#define ERI_RBT_GT	4

#define ERI_DECALRE_RBTREE(attr, pfx, tree_type, node_type, key_type) \
attr __attribute__ ((unused)) void pfx##_rbt_insert (tree_type *tree, node_type *node);	\
attr __attribute__ ((unused)) void pfx##_rbt_remove (tree_type *tree, node_type *node);	\
attr __attribute__ ((unused)) node_type *pfx##_rbt_get (tree_type *tree, key_type *key, int flags);	\
attr __attribute__ ((unused)) node_type *pfx##_rbt_get_first (tree_type *tree);		\
attr __attribute__ ((unused)) node_type *pfx##_rbt_get_next (node_type *node);		\
attr __attribute__ ((unused)) size_t pfx##_rbt_get_size (tree_type *tree);

#define ERI_DECALRE_RBTREE1(attr, pfx, tree_type, node_type) \
ERI_DECALRE_RBTREE (attr, pfx, tree_type, node_type, node_type)

#define _RBT_RED	0
#define _RBT_BLACK	1

#ifndef NO_CHECK
#define _RBT_CHECK(...) __VA_ARGS__
#else
#define _RBT_CHECK(...)
#endif

#define ERI_DEFINE_RBTREE(attr, pfx, tree_type, node_type, key_type, less_than) \
static int									\
pfx##_rbt_check_recurse (tree_type *tree, node_type *n, node_type **v)		\
{										\
  if (! n) return 0;								\
										\
  if (n->pfx##_rbt_color == _RBT_RED)						\
    {										\
      eri_assert (! n->pfx##_rbt_left						\
		  || n->pfx##_rbt_left->pfx##_rbt_color == _RBT_BLACK);		\
      eri_assert (! n->pfx##_rbt_right						\
		  || n->pfx##_rbt_right->pfx##_rbt_color == _RBT_BLACK);	\
    }										\
										\
  int h = pfx##_rbt_check_recurse (tree, n->pfx##_rbt_left, v);			\
  eri_assert (! *v || less_than (tree, (key_type *) *v, (key_type *) n));	\
  v = &n;									\
  eri_assert (h == pfx##_rbt_check_recurse (tree, n->pfx##_rbt_right, v));	\
  eri_assert (*v == n || less_than (tree, (key_type *) n, (key_type *)*v));	\
										\
  return h + (n->pfx##_rbt_color == _RBT_BLACK);				\
}										\
										\
static void __attribute__ ((unused))						\
pfx##_rbt_check (tree_type *tree)						\
{										\
  if (tree->pfx##_rbt_root)							\
    eri_assert (tree->pfx##_rbt_root->pfx##_rbt_color == _RBT_BLACK);		\
										\
  node_type *v = 0;								\
  pfx##_rbt_check_recurse (tree, tree->pfx##_rbt_root, &v);			\
}										\
										\
										\
static __attribute__ ((always_inline)) inline node_type *			\
pfx##_rbt_parent (node_type *n)							\
{										\
  return n->pfx##_rbt_parent;							\
}										\
										\
static __attribute__ ((always_inline)) inline node_type *			\
pfx##_rbt_grandparent (node_type *n)						\
{										\
  return pfx##_rbt_parent (n) ? pfx##_rbt_parent (pfx##_rbt_parent (n)) : 0;	\
}										\
										\
static __attribute__ ((always_inline)) inline node_type *			\
pfx##_rbt_sibling (node_type *n)						\
{										\
  node_type *p = pfx##_rbt_parent (n);						\
  if (! p) return 0;								\
  return n == p->pfx##_rbt_left ? p->pfx##_rbt_right : p->pfx##_rbt_left;	\
}										\
										\
static __attribute__ ((always_inline)) inline node_type *			\
pfx##_rbt_uncle (node_type *n)							\
{										\
  return pfx##_rbt_grandparent (n)						\
	 ? pfx##_rbt_sibling (pfx##_rbt_parent (n)) : 0;			\
}										\
										\
static void									\
pfx##_rbt_rotate_left (tree_type *tree, node_type *n)				\
{										\
  node_type *p = pfx##_rbt_parent (n);						\
  node_type *nn = n->pfx##_rbt_right;						\
  n->pfx##_rbt_right = nn->pfx##_rbt_left;					\
										\
  if (nn->pfx##_rbt_left) nn->pfx##_rbt_left->pfx##_rbt_parent = n;		\
  nn->pfx##_rbt_parent = p;							\
										\
  if (! p) tree->pfx##_rbt_root = nn;						\
  else if (n == p->pfx##_rbt_left) p->pfx##_rbt_left = nn;			\
  else p->pfx##_rbt_right = nn;							\
										\
  nn->pfx##_rbt_left = n;							\
  n->pfx##_rbt_parent = nn;							\
}										\
										\
static void									\
pfx##_rbt_rotate_right (tree_type *tree, node_type *n)				\
{										\
  node_type *p = pfx##_rbt_parent (n);						\
  node_type *nn = n->pfx##_rbt_left;						\
  n->pfx##_rbt_left = nn->pfx##_rbt_right;					\
										\
  if (nn->pfx##_rbt_right) nn->pfx##_rbt_right->pfx##_rbt_parent = n;		\
  nn->pfx##_rbt_parent = p;							\
										\
  if (! p) tree->pfx##_rbt_root = nn;						\
  else if (n == p->pfx##_rbt_right) p->pfx##_rbt_right = nn;			\
  else p->pfx##_rbt_left = nn;							\
										\
  nn->pfx##_rbt_right = n;							\
  n->pfx##_rbt_parent = nn;							\
}										\
										\
static void									\
pfx##_rbt_insert_recurse (tree_type *tree, node_type *r, node_type *n)		\
{										\
  if (less_than (tree, (key_type *) n, (key_type *) r))				\
    {										\
      if (r->pfx##_rbt_left)							\
	pfx##_rbt_insert_recurse (tree, r->pfx##_rbt_left, n);			\
      else									\
	{									\
	  r->pfx##_rbt_left = n;						\
	  n->pfx##_rbt_parent = r;						\
	}									\
    }										\
  else if (less_than (tree, (key_type *) r, (key_type *) n))			\
    {										\
      if (r->pfx##_rbt_right)							\
	pfx##_rbt_insert_recurse (tree, r->pfx##_rbt_right, n);			\
      else									\
	{									\
	  r->pfx##_rbt_right = n;						\
	  n->pfx##_rbt_parent = r;						\
	}									\
    }										\
  else eri_assert (0);								\
}										\
										\
static void									\
pfx##_rbt_insert_repair (tree_type *tree, node_type *n)				\
{										\
  if (! pfx##_rbt_parent (n)) n->pfx##_rbt_color = _RBT_BLACK;			\
  else if (pfx##_rbt_parent (n)->pfx##_rbt_color == _RBT_RED)			\
    {										\
      if (pfx##_rbt_uncle (n)							\
	  && pfx##_rbt_uncle (n)->pfx##_rbt_color == _RBT_RED)			\
	{									\
	  pfx##_rbt_parent (n)->pfx##_rbt_color = _RBT_BLACK;			\
	  pfx##_rbt_uncle (n)->pfx##_rbt_color = _RBT_BLACK;			\
	  pfx##_rbt_grandparent (n)->pfx##_rbt_color = _RBT_RED;		\
	  pfx##_rbt_insert_repair (tree, pfx##_rbt_grandparent (n));		\
	}									\
      else									\
	{									\
	  node_type *p = pfx##_rbt_parent (n);					\
	  node_type *g = pfx##_rbt_grandparent (n);				\
										\
	  if (p == g->pfx##_rbt_left)						\
	    {									\
	      if (n == p->pfx##_rbt_right)					\
		{								\
		  pfx##_rbt_rotate_left (0, p);					\
		  n = n->pfx##_rbt_left;					\
		}								\
	      pfx##_rbt_rotate_right (tree, g);					\
	    }									\
	  else									\
	    {									\
	      if (n == p->pfx##_rbt_left)					\
		{								\
		  pfx##_rbt_rotate_right (0, p);				\
		  n = n->pfx##_rbt_right;					\
		}								\
	      pfx##_rbt_rotate_left (tree, g);					\
	    }									\
	  pfx##_rbt_parent (n)->pfx##_rbt_color = _RBT_BLACK;			\
	  g->pfx##_rbt_color = _RBT_RED;					\
	}									\
    }										\
}										\
										\
attr __attribute__ ((unused)) void						\
pfx##_rbt_insert (tree_type *tree, node_type *node)				\
{										\
  node->pfx##_rbt_color = _RBT_RED;						\
  node->pfx##_rbt_parent = node->pfx##_rbt_left = node->pfx##_rbt_right = 0;	\
										\
  if (! tree->pfx##_rbt_root) tree->pfx##_rbt_root = node;			\
  else pfx##_rbt_insert_recurse (tree, tree->pfx##_rbt_root, node);		\
										\
  pfx##_rbt_insert_repair (tree, node);						\
  ++tree->pfx##_rbt_size;							\
										\
  _RBT_CHECK (pfx##_rbt_check (tree));						\
}										\
										\
static void									\
pfx##_rbt_remove_repair (tree_type *tree, node_type *p, node_type *n)		\
{										\
  if (! p) return;								\
										\
  node_type *s = n == p->pfx##_rbt_left						\
		      ? p->pfx##_rbt_right : p->pfx##_rbt_left;			\
  if (s->pfx##_rbt_color == _RBT_RED)						\
    {										\
      p->pfx##_rbt_color = _RBT_RED;						\
      s->pfx##_rbt_color = _RBT_BLACK;						\
      if (n == p->pfx##_rbt_left)						\
	pfx##_rbt_rotate_left (tree, p);					\
      else									\
	pfx##_rbt_rotate_right (tree, p);					\
      s = n == p->pfx##_rbt_left ? p->pfx##_rbt_right : p->pfx##_rbt_left;	\
    }										\
										\
  if ((! s->pfx##_rbt_left							\
       || s->pfx##_rbt_left->pfx##_rbt_color == _RBT_BLACK)			\
      && (! s->pfx##_rbt_right							\
	  || s->pfx##_rbt_right->pfx##_rbt_color == _RBT_BLACK))		\
    {										\
      s->pfx##_rbt_color = _RBT_RED;						\
      if (p->pfx##_rbt_color == _RBT_BLACK)					\
	pfx##_rbt_remove_repair (tree, pfx##_rbt_parent (p), p);		\
      else									\
	p->pfx##_rbt_color = _RBT_BLACK;					\
    }										\
  else										\
    {										\
      if (n == p->pfx##_rbt_left						\
	  && (s->pfx##_rbt_left							\
	      && s->pfx##_rbt_left->pfx##_rbt_color == _RBT_RED)		\
	  && (! s->pfx##_rbt_right						\
	      || s->pfx##_rbt_right->pfx##_rbt_color == _RBT_BLACK))		\
	{									\
	  s->pfx##_rbt_color = _RBT_RED;					\
	  s->pfx##_rbt_left->pfx##_rbt_color = _RBT_BLACK;			\
	  pfx##_rbt_rotate_right (0, s);					\
	  s = p->pfx##_rbt_right;						\
	}									\
      else if (n == p->pfx##_rbt_right						\
	       && (! s->pfx##_rbt_left						\
		   || s->pfx##_rbt_left->pfx##_rbt_color == _RBT_BLACK)		\
	       && (s->pfx##_rbt_right						\
		   && s->pfx##_rbt_right->pfx##_rbt_color == _RBT_RED))		\
	{									\
	  s->pfx##_rbt_color = _RBT_RED;					\
	  s->pfx##_rbt_right->pfx##_rbt_color = _RBT_BLACK;			\
	  pfx##_rbt_rotate_left (0, s);						\
	  s = p->pfx##_rbt_left;						\
	}									\
										\
      s->pfx##_rbt_color = p->pfx##_rbt_color;					\
      p->pfx##_rbt_color = _RBT_BLACK;						\
										\
      if (n == p->pfx##_rbt_left)						\
	{									\
	  s->pfx##_rbt_right->pfx##_rbt_color = _RBT_BLACK;			\
	  pfx##_rbt_rotate_left (tree, p);					\
	}									\
      else									\
	{									\
	  s->pfx##_rbt_left->pfx##_rbt_color = _RBT_BLACK;			\
	  pfx##_rbt_rotate_right (tree, p);					\
	}									\
    }										\
}										\
										\
static void									\
pfx##_rbt_remove_one_child (tree_type *tree, node_type *n)			\
{										\
  node_type *c = ! n->pfx##_rbt_right ? n->pfx##_rbt_left : n->pfx##_rbt_right;	\
										\
  if (c) c->pfx##_rbt_parent = pfx##_rbt_parent (n);				\
  if (! pfx##_rbt_parent (n)) tree->pfx##_rbt_root = c;				\
  else if (n == pfx##_rbt_parent (n)->pfx##_rbt_left)				\
    pfx##_rbt_parent (n)->pfx##_rbt_left = c;					\
  else pfx##_rbt_parent (n)->pfx##_rbt_right = c;				\
										\
  if (n->pfx##_rbt_color == _RBT_BLACK)						\
    {										\
      if (c && c->pfx##_rbt_color == _RBT_RED)					\
	c->pfx##_rbt_color = _RBT_BLACK;					\
      else									\
	pfx##_rbt_remove_repair (tree, pfx##_rbt_parent (n), c);		\
    }										\
}										\
										\
attr __attribute__ ((unused)) void						\
pfx##_rbt_remove (tree_type *tree, node_type *node)				\
{										\
  if (node->pfx##_rbt_left && node->pfx##_rbt_right)				\
    {										\
      node_type *m = node->pfx##_rbt_left;					\
      while (m->pfx##_rbt_right) m = m->pfx##_rbt_right;			\
      pfx##_rbt_remove_one_child (tree, m);					\
										\
      m->pfx##_rbt_parent = pfx##_rbt_parent (node);				\
      m->pfx##_rbt_left = node->pfx##_rbt_left;					\
      m->pfx##_rbt_right = node->pfx##_rbt_right;				\
      m->pfx##_rbt_color = node->pfx##_rbt_color;				\
										\
      if (! pfx##_rbt_parent (m)) tree->pfx##_rbt_root = m;			\
      else if (node == pfx##_rbt_parent (m)->pfx##_rbt_left)			\
	pfx##_rbt_parent (m)->pfx##_rbt_left = m;				\
      else pfx##_rbt_parent (m)->pfx##_rbt_right = m;				\
										\
      if (m->pfx##_rbt_left) m->pfx##_rbt_left->pfx##_rbt_parent = m;		\
      if (m->pfx##_rbt_right) m->pfx##_rbt_right->pfx##_rbt_parent = m;		\
    }										\
  else pfx##_rbt_remove_one_child (tree, node);					\
										\
  --tree->pfx##_rbt_size;							\
  _RBT_CHECK (pfx##_rbt_check (tree));						\
}										\
										\
attr __attribute__ ((unused)) node_type *					\
pfx##_rbt_get (tree_type *tree, key_type *key, int flags)			\
{										\
  eri_assert (! (flags & ERI_RBT_LT) || ! (flags & ERI_RBT_GT));		\
  node_type *r = tree->pfx##_rbt_root;						\
  node_type *v = 0;								\
  while (r)									\
    {										\
      if (less_than (tree, (key_type *) r, key))				\
	{									\
	  if ((flags & ~ERI_RBT_EQ) == ERI_RBT_LT) v = r;			\
	  r = r->pfx##_rbt_right;						\
	}									\
      else if (less_than (tree, key, (key_type *) (r)))				\
	{									\
	  if ((flags & ~ERI_RBT_EQ) == ERI_RBT_GT) v = r;			\
	  r = r->pfx##_rbt_left;						\
	}									\
      else									\
	{									\
	  if (flags & ERI_RBT_EQ) return r;					\
	  else if (flags == ERI_RBT_LT) r = r->pfx##_rbt_left;			\
	  else if (flags == ERI_RBT_GT) r = r->pfx##_rbt_right;			\
	  else eri_assert (0);							\
	}									\
    }										\
  return v;									\
}										\
										\
static node_type *								\
pfx##_rbt_get_min (node_type *n)						\
{										\
  while (n->pfx##_rbt_left) n = n->pfx##_rbt_left;				\
  return n;									\
}										\
										\
attr __attribute__ ((unused)) node_type *					\
pfx##_rbt_get_first (tree_type *tree)						\
{										\
  return tree->pfx##_rbt_root ? pfx##_rbt_get_min (tree->pfx##_rbt_root) : 0;	\
}										\
										\
attr __attribute__ ((unused)) node_type *					\
pfx##_rbt_get_next (node_type *node)						\
{										\
  if (node->pfx##_rbt_right) return pfx##_rbt_get_min (node->pfx##_rbt_right);	\
										\
  node_type *n = node;								\
  while (pfx##_rbt_parent (n) && n == pfx##_rbt_parent (n)->pfx##_rbt_right)	\
    n = pfx##_rbt_parent (n);							\
  return pfx##_rbt_parent (n);							\
}										\
										\
attr __attribute__ ((unused)) size_t						\
pfx##_rbt_get_size (tree_type *tree)						\
{										\
  return tree->pfx##_rbt_size;							\
}

#define ERI_DEFINE_RBTREE1(attr, pfx, tree_type, node_type, less_than) \
ERI_DEFINE_RBTREE (attr, pfx, tree_type, node_type, node_type, less_than)

#define ERI_RBT_FOREACH(pfx, tree, iter) \
  for (iter = pfx##_rbt_get_first (tree); iter; iter = pfx##_rbt_get_next (iter))
#define ERI_RBT_FOREACH_SAFE(pfx, tree, iter, next) \
  for (iter = pfx##_rbt_get_first (tree); iter && ({ next = pfx##_rbt_get_next (iter); 1; }); iter = next)

#endif
