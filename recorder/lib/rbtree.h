#ifndef ERS_RBTREE_H
#define ERS_RBTREE_H

#include "util.h"

/* tree_type { ERS_RBT_TREE_FIELDS (pfx, node_type) ... };
   node_type { key_type key; ERS_RBT_NODE_FIELDS (pfx, node_type) ... };
   int less_than (tree_type *tree, key_type *k1, key_type *k2);

   Zero out the ERS_RBT_TREE_FIELDS or call ERS_RBT_INIT_TREE before use.

   The key has to be the first field or the node to allow casting.
   The order of all other fields are irrelevant.

   Bit fileds of ERS_RBT_NODE_FIELDS are at the beginning. */

#define ERS_RBT_INIT_TREE(pfx, tree) do { (tree)->pfx##_root = 0; } while (0)
#define ERS_RBT_TREE_FIELDS(pfx, node_type) node_type *pfx##_root;
#define ERS_RBT_NODE_FIELDS(pfx, node_type) \
  unsigned char pfx##_color : 1; node_type *pfx##_parent, *pfx##_left, *pfx##_right;

#define ERS_RBT_EQ	1
#define ERS_RBT_LT	2
#define ERS_RBT_GT	4

#define ERS_DECALRE_RBTREE(attr, pfx, tree_type, node_type, key_type) \
attr __attribute__ ((used)) void pfx##_insert (tree_type *tree, node_type *node);	\
attr __attribute__ ((used)) void pfx##_remove (tree_type *tree, node_type *node);	\
attr __attribute__ ((used)) node_type *pfx##_get (tree_type *tree, key_type *key, int flags);	\
attr __attribute__ ((used)) node_type *pfx##_get_first (tree_type *tree);		\
attr __attribute__ ((used)) node_type *pfx##_get_next (node_type *node);

#define ERS_DECALRE_RBTREE1(attr, pfx, tree_type, node_type) \
ERS_DECALRE_RBTREE (attr, pfx, tree_type, node_type, node_type)

#define _RBT_RED	0
#define _RBT_BLACK	1

#define ERS_DEFINE_RBTREE(attr, pfx, tree_type, node_type, key_type, less_than) \
static int									\
pfx##_check_recurse (tree_type *tree, node_type *n, node_type **v)		\
{										\
  if (! n) return 0;								\
										\
  if (n->pfx##_color == _RBT_RED)						\
    {										\
      ers_assert (! n->pfx##_left						\
		  || n->pfx##_left->pfx##_color == _RBT_BLACK);			\
      ers_assert (! n->pfx##_right						\
		  || n->pfx##_right->pfx##_color == _RBT_BLACK);		\
    }										\
										\
  int h = pfx##_check_recurse (tree, n->pfx##_left, v);				\
  ers_assert (! *v || less_than (tree, (key_type *) *v, (key_type *) n));	\
  v = &n;									\
  ers_assert (h == pfx##_check_recurse (tree, n->pfx##_right, v));		\
  ers_assert (*v == n || less_than (tree, (key_type *) n, (key_type *)*v));	\
										\
  return h + (n->pfx##_color == _RBT_BLACK);					\
}										\
										\
static void									\
pfx##_check (tree_type *tree)							\
{										\
  if (tree->pfx##_root)								\
    ers_assert (tree->pfx##_root->pfx##_color == _RBT_BLACK);			\
										\
  node_type *v = 0;								\
  pfx##_check_recurse (tree, tree->pfx##_root, &v);				\
}										\
										\
										\
static __attribute__ ((always_inline)) inline node_type *			\
pfx##_parent (node_type *n)							\
{										\
  return n->pfx##_parent;							\
}										\
										\
static __attribute__ ((always_inline)) inline node_type *			\
pfx##_grandparent (node_type *n)						\
{										\
  return pfx##_parent (n) ? pfx##_parent (pfx##_parent (n)) : 0;		\
}										\
										\
static __attribute__ ((always_inline)) inline node_type *			\
pfx##_sibling (node_type *n)							\
{										\
  node_type *p = pfx##_parent (n);						\
  if (! p) return 0;								\
  return n == p->pfx##_left ? p->pfx##_right : p->pfx##_left;			\
}										\
										\
static __attribute__ ((always_inline)) inline node_type *			\
pfx##_uncle (node_type *n)							\
{										\
  return pfx##_grandparent (n) ? pfx##_sibling (pfx##_parent (n)) : 0;		\
}										\
										\
static void									\
pfx##_rotate_left (tree_type *tree, node_type *n)				\
{										\
  node_type *p = pfx##_parent (n);						\
  node_type *nn = n->pfx##_right;						\
  n->pfx##_right = nn->pfx##_left;						\
										\
  if (nn->pfx##_left) nn->pfx##_left->pfx##_parent = n;				\
  nn->pfx##_parent = p;								\
										\
  if (! p) tree->pfx##_root = nn;						\
  else if (n == p->pfx##_left) p->pfx##_left = nn;				\
  else p->pfx##_right = nn;							\
										\
  nn->pfx##_left = n;								\
  n->pfx##_parent = nn;								\
}										\
										\
static void									\
pfx##_rotate_right (tree_type *tree, node_type *n)				\
{										\
  node_type *p = pfx##_parent (n);						\
  node_type *nn = n->pfx##_left;						\
  n->pfx##_left = nn->pfx##_right;						\
										\
  if (nn->pfx##_right) nn->pfx##_right->pfx##_parent = n;			\
  nn->pfx##_parent = p;								\
										\
  if (! p) tree->pfx##_root = nn;						\
  else if (n == p->pfx##_right) p->pfx##_right = nn;				\
  else p->pfx##_left = nn;							\
										\
  nn->pfx##_right = n;								\
  n->pfx##_parent = nn;								\
}										\
										\
static void									\
pfx##_insert_recurse (tree_type *tree, node_type *r, node_type *n)		\
{										\
  if (less_than (tree, (key_type *) n, (key_type *) r))				\
    {										\
      if (r->pfx##_left) pfx##_insert_recurse (tree, r->pfx##_left, n);		\
      else									\
	{									\
	  r->pfx##_left = n;							\
	  n->pfx##_parent = r;							\
	}									\
    }										\
  else if (less_than (tree, (key_type *) r, (key_type *) n))			\
    {										\
      if (r->pfx##_right) pfx##_insert_recurse (tree, r->pfx##_right, n);	\
      else									\
	{									\
	  r->pfx##_right = n;							\
	  n->pfx##_parent = r;							\
	}									\
    }										\
  else ers_assert (0);								\
}										\
										\
static void									\
pfx##_insert_repair (tree_type *tree, node_type *n)				\
{										\
  if (! pfx##_parent (n)) n->pfx##_color = _RBT_BLACK;				\
  else if (pfx##_parent (n)->pfx##_color == _RBT_RED)				\
    {										\
      if (pfx##_uncle (n) && pfx##_uncle (n)->pfx##_color == _RBT_RED)		\
	{									\
	  pfx##_parent (n)->pfx##_color = _RBT_BLACK;				\
	  pfx##_uncle (n)->pfx##_color = _RBT_BLACK;				\
	  pfx##_grandparent (n)->pfx##_color = _RBT_RED;			\
	  pfx##_insert_repair (tree, pfx##_grandparent (n));			\
	}									\
      else									\
	{									\
	  node_type *p = pfx##_parent (n);					\
	  node_type *g = pfx##_grandparent (n);					\
										\
	  if (p == g->pfx##_left)						\
	    {									\
	      if (n == p->pfx##_right)						\
		{								\
		  pfx##_rotate_left (0, p);					\
		  n = n->pfx##_left;						\
		}								\
	      pfx##_rotate_right (tree, g);					\
	    }									\
	  else									\
	    {									\
	      if (n == p->pfx##_left)						\
		{								\
		  pfx##_rotate_right (0, p);					\
		  n = n->pfx##_right;						\
		}								\
	      pfx##_rotate_left (tree, g);					\
	    }									\
	  pfx##_parent (n)->pfx##_color = _RBT_BLACK;				\
	  g->pfx##_color = _RBT_RED;						\
	}									\
    }										\
}										\
										\
attr __attribute__ ((used)) void						\
pfx##_insert (tree_type *tree, node_type *node)					\
{										\
  node->pfx##_color = _RBT_RED;							\
  node->pfx##_parent = node->pfx##_left = node->pfx##_right = 0;		\
										\
  if (! tree->pfx##_root) tree->pfx##_root = node;				\
  else pfx##_insert_recurse (tree, tree->pfx##_root, node);			\
										\
  pfx##_insert_repair (tree, node);						\
										\
  pfx##_check (tree); /* XXX safety check */					\
}										\
										\
static void									\
pfx##_remove_repair (tree_type *tree, node_type *p, node_type *n)		\
{										\
  if (! p) return;								\
										\
  node_type *s = n == p->pfx##_left ? p->pfx##_right : p->pfx##_left;		\
  if (s->pfx##_color == _RBT_RED)						\
    {										\
      p->pfx##_color = _RBT_RED;						\
      s->pfx##_color = _RBT_BLACK;						\
      if (n == p->pfx##_left)							\
	pfx##_rotate_left (tree, p);						\
      else									\
	pfx##_rotate_right (tree, p);						\
      s = n == p->pfx##_left ? p->pfx##_right : p->pfx##_left;			\
    }										\
										\
  if ((! s->pfx##_left || s->pfx##_left->pfx##_color == _RBT_BLACK)		\
      && (! s->pfx##_right || s->pfx##_right->pfx##_color == _RBT_BLACK))	\
    {										\
      s->pfx##_color = _RBT_RED;						\
      if (p->pfx##_color == _RBT_BLACK)						\
	pfx##_remove_repair (tree, pfx##_parent (p), p);			\
      else									\
	p->pfx##_color = _RBT_BLACK;						\
    }										\
  else										\
    {										\
      if (n == p->pfx##_left							\
	  && (s->pfx##_left && s->pfx##_left->pfx##_color == _RBT_RED)		\
	  && (! s->pfx##_right || s->pfx##_right->pfx##_color == _RBT_BLACK))	\
	{									\
	  s->pfx##_color = _RBT_RED;						\
	  s->pfx##_left->pfx##_color = _RBT_BLACK;				\
	  pfx##_rotate_right (0, s);						\
	  s = p->pfx##_right;							\
	}									\
      else if (n == p->pfx##_right						\
	       && (! s->pfx##_left || s->pfx##_left->pfx##_color == _RBT_BLACK)	\
	       && (s->pfx##_right && s->pfx##_right->pfx##_color == _RBT_RED))	\
	{									\
	  s->pfx##_color = _RBT_RED;						\
	  s->pfx##_right->pfx##_color = _RBT_BLACK;				\
	  pfx##_rotate_left (0, s);						\
	  s = p->pfx##_left;							\
	}									\
										\
      s->pfx##_color = p->pfx##_color;						\
      p->pfx##_color = _RBT_BLACK;						\
										\
      if (n == p->pfx##_left)							\
	{									\
	  s->pfx##_right->pfx##_color = _RBT_BLACK;				\
	  pfx##_rotate_left (tree, p);						\
	}									\
      else									\
	{									\
	  s->pfx##_left->pfx##_color = _RBT_BLACK;				\
	  pfx##_rotate_right (tree, p);						\
	}									\
    }										\
}										\
										\
static void									\
pfx##_remove_one_child (tree_type *tree, node_type *n)				\
{										\
  node_type *c = ! n->pfx##_right ? n->pfx##_left : n->pfx##_right;		\
										\
  if (c) c->pfx##_parent = pfx##_parent (n);					\
  if (! pfx##_parent (n)) tree->pfx##_root = c;					\
  else if (n == pfx##_parent (n)->pfx##_left) pfx##_parent (n)->pfx##_left = c;	\
  else pfx##_parent (n)->pfx##_right = c;					\
										\
  if (n->pfx##_color == _RBT_BLACK)						\
    {										\
      if (c && c->pfx##_color == _RBT_RED)					\
	c->pfx##_color = _RBT_BLACK;						\
      else									\
	pfx##_remove_repair (tree, pfx##_parent (n), c);			\
    }										\
}										\
										\
attr __attribute__ ((used)) void						\
pfx##_remove (tree_type *tree, node_type *node)					\
{										\
  if (node->pfx##_left && node->pfx##_right)					\
    {										\
      node_type *m = node->pfx##_left;						\
      while (m->pfx##_right) m = m->pfx##_right;				\
      pfx##_remove_one_child (tree, m);						\
										\
      m->pfx##_parent = pfx##_parent (node);					\
      m->pfx##_left = node->pfx##_left;						\
      m->pfx##_right = node->pfx##_right;					\
      m->pfx##_color = node->pfx##_color;					\
										\
      if (! pfx##_parent (m)) tree->pfx##_root = m;				\
      else if (node == pfx##_parent (m)->pfx##_left)				\
	pfx##_parent (m)->pfx##_left = m;					\
      else pfx##_parent (m)->pfx##_right = m;					\
										\
      if (m->pfx##_left) m->pfx##_left->pfx##_parent = m;			\
      if (m->pfx##_right) m->pfx##_right->pfx##_parent = m;			\
    }										\
  else pfx##_remove_one_child (tree, node);					\
										\
  pfx##_check (tree); /* XXX safety check */					\
}										\
										\
attr __attribute__ ((used)) node_type *						\
pfx##_get (tree_type *tree, key_type *key, int flags)				\
{										\
  ers_assert (! (flags & ERS_RBT_LT) || ! (flags & ERS_RBT_GT));		\
  node_type *r = tree->pfx##_root;						\
  node_type *v = 0;								\
  while (r)									\
    {										\
      if (less_than (tree, (key_type *) r, key))				\
	{									\
	  if ((flags & ~ERS_RBT_EQ) == ERS_RBT_LT) v = r;			\
	  r = r->pfx##_right;							\
	}									\
      else if (less_than (tree, key, (key_type *) (r)))				\
	{									\
	  if ((flags & ~ERS_RBT_EQ) == ERS_RBT_GT) v = r;			\
	  r = r->pfx##_left;							\
	}									\
      else									\
	{									\
	  if (flags & ERS_RBT_EQ) return r;					\
	  else if (flags == ERS_RBT_LT) r = r->pfx##_left;			\
	  else if (flags == ERS_RBT_GT) r = r->pfx##_right;			\
	  else ers_assert (0);							\
	}									\
    }										\
  return v;									\
}										\
										\
static node_type *								\
pfx##_get_min (node_type *n)							\
{										\
  while (n->pfx##_left) n = n->pfx##_left;					\
  return n;									\
}										\
										\
attr __attribute__ ((used)) node_type *						\
pfx##_get_first (tree_type *tree)						\
{										\
  return tree->pfx##_root ? pfx##_get_min (tree->pfx##_root) : 0;		\
}										\
										\
attr __attribute__ ((used)) node_type *						\
pfx##_get_next (node_type *node)						\
{										\
  if (node->pfx##_right) return pfx##_get_min (node->pfx##_right);		\
										\
  node_type *n = node;								\
  while (pfx##_parent (n) && n == pfx##_parent (n)->pfx##_right)		\
    n = pfx##_parent (n);							\
  return pfx##_parent (n);							\
}

#define ERS_DEFINE_RBTREE1(attr, pfx, tree_type, node_type, less_than) \
ERS_DEFINE_RBTREE (attr, pfx, tree_type, node_type, node_type, less_than)

#define ERS_RBT_FOREACH(pfx, tree, iter) \
  for (iter = pfx##_get_first (tree); iter; iter = pfx##_get_next (iter))
#define ERS_RBT_FOREACH_SAFE(pfx, tree, iter, next) \
  for (iter = pfx##_get_first (tree); iter && ({ next = pfx##_get_next (iter); 1; }); iter = next)

#endif
