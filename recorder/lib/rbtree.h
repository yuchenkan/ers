#ifndef ERS_RBTREE_H
#define ERS_RBTREE_H

#include "util.h"

/* tree_type { ERS_RBT_TREE_FIELDS (node_type) ... };
   node_type { key_type key; ERS_RBT_NODE_FIELDS (node_type) ... };
   int less_than (tree_type *tree, key_type *k1, key_type *k2);

   Zero out the ERS_RBT_TREE_FIELDS or call ERS_RBT_INIT_TREE before use.

   The key has to be the first field or the node to allow casting.
   The order of all other fields are irrelevant.

   Bit fileds of ERS_RBT_NODE_FIELDS are in the beginning. */

#define ERS_RBT_INIT_TREE(tree) do { (tree)->root = NULL; } while (0)
#define ERS_RBT_TREE_FIELDS(node_type) node_type *root;
#define ERS_RBT_NODE_FIELDS(node_type) unsigned char color : 1; node_type *parent, *left, *right;

#define ERS_RBT_EQ	1
#define ERS_RBT_LT	2
#define ERS_RBT_GT	4

#define ERS_DECALRE_RBTREE(attr, pfx, tree_type, node_type, key_type) \
attr __attribute__ ((used)) void pfx##_insert (tree_type *tree, node_type *node);	\
attr __attribute__ ((used)) void pfx##_remove (tree_type *tree, node_type *node);	\
attr __attribute__ ((used)) node_type *pfx##_get (tree_type *tree, key_type *key, int flags = ERS_RBT_EQ)

#define ERS_DECALRE_RBTREE1(attr, pfx, tree_type, node_type) \
ERS_DECLARE_RBTREE (attr, pfx, tree_type, node_type, node_type)

#define _RBT_RED		0
#define _RBT_BLACK	1

#define ERS_DEFINE_RBTREE(attr, pfx, tree_type, node_type, key_type, less_than) \
static int									\
pfx##_check_recurse (tree_type *tree, node_type *n, node_type **v)		\
{										\
  if (! n) return 0;								\
										\
  if (n->color == _RBT_RED)							\
    {										\
      ers_assert (! n->left || n->left->color == _RBT_BLACK);			\
      ers_assert (! n->right || n->right->color == _RBT_BLACK);			\
    }										\
										\
  int h = pfx##_check_recurse (tree, n->left, v);				\
  ers_assert (! *v || less_than (tree, (key_type *) *v, (key_type *) n));	\
  v = &n;									\
  ers_assert (h == pfx##_check_recurse (tree, n->right, v));			\
  ers_assert (*v == n || less_than (tree, (key_type *) n, (key_type *)*v));	\
										\
  return h + (n->color == _RBT_BLACK);						\
}										\
										\
static void									\
pfx##_check (tree_type *tree)							\
{										\
  if (tree->root) ers_assert (tree->root->color == _RBT_BLACK);			\
										\
  node_type *v = NULL;								\
  pfx##_check_recurse (tree, tree->root, &v);					\
}										\
										\
										\
static inline node_type *							\
pfx##_parent (node_type *n)							\
{										\
  return n->parent;								\
}										\
										\
static inline node_type *							\
pfx##_grandparent (node_type *n)						\
{										\
  return pfx##_parent (n) ? pfx##_parent (pfx##_parent (n)) : NULL;		\
}										\
										\
static inline node_type *							\
pfx##_sibling (node_type *n)							\
{										\
  node_type *p = pfx##_parent (n);						\
  if (! p) return NULL;								\
  return n == p->left ? p->right : p->left;					\
}										\
										\
static inline node_type *							\
pfx##_uncle (node_type *n)							\
{										\
 return pfx##_grandparent (n) ? pfx##_sibling (pfx##_parent (n)) : NULL;	\
}										\
										\
static void									\
pfx##_rotate_left (tree_type *tree, node_type *n)				\
{										\
  node_type *p = pfx##_parent (n);						\
  node_type *nn = n->right;							\
  n->right = nn->left;								\
										\
  if (nn->left) nn->left->parent = n;						\
  nn->parent = p;								\
										\
  if (! p) tree->root = nn;							\
  else if (n == p->left) p->left = nn;						\
  else p->right = nn;								\
										\
  nn->left = n;									\
  n->parent = nn;								\
}										\
										\
static void									\
pfx##_rotate_right (tree_type *tree, node_type *n)				\
{										\
  node_type *p = pfx##_parent (n);						\
  node_type *nn = n->left;							\
  n->left = nn->right;								\
										\
  if (nn->right) nn->right->parent = n;						\
  nn->parent = p;								\
										\
  if (! p) tree->root = nn;							\
  else if (n == p->right) p->right = nn;					\
  else p->left = nn;								\
										\
  nn->right = n;								\
  n->parent = nn;								\
}										\
										\
static void									\
pfx##_insert_recurse (tree_type *tree, node_type *r, node_type *n)		\
{										\
  if (less_than (tree, (key_type *) n, (key_type *) r))				\
    {										\
      if (r->left) pfx##_insert_recurse (tree, r->left, n);			\
      else									\
	{									\
	  r->left = n;								\
	  n->parent = r;							\
	}									\
    }										\
  else if (less_than (tree, (key_type *) r, (key_type *) n))			\
    {										\
      if (r->right) pfx##_insert_recurse (tree, r->right, n);			\
      else									\
	{									\
	  r->right = n;								\
	  n->parent = r;							\
	}									\
    }										\
  else ers_assert (0);								\
}										\
										\
static void									\
pfx##_insert_repair (tree_type *tree, node_type *n)				\
{										\
  if (! pfx##_parent (n)) n->color = _RBT_BLACK;				\
  else if (pfx##_parent (n)->color == _RBT_RED)					\
    {										\
      if (pfx##_uncle (n) && pfx##_uncle (n)->color == _RBT_RED)		\
	{									\
	  pfx##_parent (n)->color = _RBT_BLACK;					\
	  pfx##_uncle (n)->color = _RBT_BLACK;					\
	  pfx##_grandparent (n)->color = _RBT_RED;				\
	  pfx##_insert_repair (tree, pfx##_grandparent (n));			\
	}									\
      else									\
	{									\
	  node_type *p = pfx##_parent (n);					\
	  node_type *g = pfx##_grandparent (n);					\
										\
	  if (p == g->left)							\
	    {									\
	      if (n == p->right)						\
		{								\
		  pfx##_rotate_left (NULL, p);					\
		  n = n->left;							\
		}								\
	      pfx##_rotate_right (tree, g);					\
	    }									\
	  else									\
	    {									\
	      if (n == p->left)							\
		{								\
		  pfx##_rotate_right (NULL, p);					\
		  n = n->right;							\
		}								\
	      pfx##_rotate_left (tree, g);					\
	    }									\
	  pfx##_parent (n)->color = _RBT_BLACK;					\
	  g->color = _RBT_RED;							\
	}									\
    }										\
}										\
										\
attr __attribute__ ((used)) void						\
pfx##_insert (tree_type *tree, node_type *n)					\
{										\
  n->color = _RBT_RED;								\
  n->parent = n->left = n->right = NULL;					\
										\
  if (! tree->root) tree->root = n;						\
  else pfx##_insert_recurse (tree, tree->root, n);				\
										\
  pfx##_insert_repair (tree, n);						\
										\
  pfx##_check (tree);								\
}										\
										\
static void									\
pfx##_remove_repair (tree_type *tree, node_type *p, node_type *n)		\
{										\
  if (! p) return;								\
										\
  node_type *s = n == p->left ? p->right : p->left;				\
  if (s->color == _RBT_RED)							\
    {										\
      p->color = _RBT_RED;							\
      s->color = _RBT_BLACK;							\
      if (n == p->left)								\
	pfx##_rotate_left (tree, p);						\
      else									\
	pfx##_rotate_right (tree, p);						\
      s = n == p->left ? p->right : p->left;					\
    }										\
										\
  if ((! s->left || s->left->color == _RBT_BLACK)				\
      && (! s->right || s->right->color == _RBT_BLACK))				\
    {										\
      s->color = _RBT_RED;							\
      if (p->color == _RBT_BLACK)						\
	pfx##_remove_repair (tree, pfx##_parent (p), p);			\
      else									\
	p->color = _RBT_BLACK;							\
    }										\
  else										\
    {										\
      if (n == p->left								\
	  && (s->left && s->left->color == _RBT_RED)				\
	  && (! s->right || s->right->color == _RBT_BLACK))			\
	{									\
	  s->color = _RBT_RED;							\
	  s->left->color = _RBT_BLACK;						\
	  pfx##_rotate_right (NULL, s);						\
	  s = p->right;								\
	}									\
      else if (n == p->right							\
	       && (! s->left || s->left->color == _RBT_BLACK)			\
	       && (s->right && s->right->color == _RBT_RED))			\
	{									\
	  s->color = _RBT_RED;							\
	  s->right->color = _RBT_BLACK;						\
	  pfx##_rotate_left (NULL, s);						\
	  s = p->left;								\
	}									\
										\
      s->color = p->color;							\
      p->color = _RBT_BLACK;							\
										\
      if (n == p->left)								\
	{									\
	  s->right->color = _RBT_BLACK;						\
	  pfx##_rotate_left (tree, p);						\
	}									\
      else									\
	{									\
	  s->left->color = _RBT_BLACK;						\
	  pfx##_rotate_right (tree, p);						\
	}									\
    }										\
}										\
										\
static void									\
pfx##_remove_one_child (tree_type *tree, node_type *n)				\
{										\
  node_type *c = ! n->right ? n->left : n->right;				\
										\
  if (c) c->parent = pfx##_parent (n);						\
  if (! pfx##_parent (n)) tree->root = c;					\
  else if (n == pfx##_parent (n)->left) pfx##_parent (n)->left = c;		\
  else pfx##_parent (n)->right = c;						\
										\
  if (n->color == _RBT_BLACK)							\
    {										\
      if (c && c->color == _RBT_RED)						\
	c->color = _RBT_BLACK;							\
      else									\
	pfx##_remove_repair (tree, pfx##_parent (n), c);			\
    }										\
}										\
										\
attr __attribute__ ((used)) void						\
pfx##_remove (tree_type *tree, node_type *n)					\
{										\
  if (n->left && n->right)							\
    {										\
      node_type *m = n->left;							\
      while (m->right) m = m->right;						\
      pfx##_remove_one_child (tree, m);						\
										\
      m->parent = pfx##_parent (n);						\
      m->left = n->left;							\
      m->right = n->right;							\
      m->color = n->color;							\
										\
      if (! pfx##_parent (m)) tree->root = m;					\
      else if (m == pfx##_parent (m)->left) pfx##_parent (m)->left = m;		\
      else pfx##_parent (m)->right = m;						\
										\
      if (m->left) m->left->parent = m;						\
      if (m->right) m->right->parent = m;					\
    }										\
  else pfx##_remove_one_child (tree, n);					\
										\
  pfx##_check (tree);								\
}										\
										\
attr __attribute__ ((used)) node_type *						\
pfx##_get (tree_type *tree, key_type *n, int flags)				\
{										\
  ers_assert (! (flags & ERS_RBT_LT) || ! (flags & ERS_RBT_GT));		\
  node_type *r = tree->root;							\
  node_type *v = NULL;								\
  while (r)									\
    {										\
      if (less_than (tree, (key_type *) r, n))					\
	{									\
	  if ((flags & ~ERS_RBT_EQ) == ERS_RBT_LT) v = r;			\
	  r = r->right;								\
	}									\
      else if (less_than (tree, n, (key_type *) (r)))				\
	{									\
	  if ((flags & ~ERS_RBT_EQ) == ERS_RBT_GT) v = r;			\
	  r = r->left;								\
	}									\
      else									\
	{									\
	  if (flags & ERS_RBT_EQ) return r;					\
	  else if (flags == ERS_RBT_LT) r = r->left;				\
	  else if (flags == ERS_RBT_GT) r = r->right;				\
	  else ers_assert (0);							\
	}									\
    }										\
  return v;									\
}

#define ERS_DEFINE_RBTREE1(attr, pfx, tree_type, node_type, less_than) \
ERS_DEFINE_RBTREE (attr, pfx, tree_type, node_type, node_type, less_than)

#endif
