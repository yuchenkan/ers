#ifndef ERI_LIB_RBTREE_H
#define ERI_LIB_RBTREE_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>

/*
 * tree_type { ERI_RBT_TREE_FIELDS (pfx, node_type) ... };
 * node_type { key_type key; ERI_RBT_NODE_FIELDS (pfx, node_type) ... };
 * uint8_t less_than (tree_type *tree, key_type *k1, key_type *k2);
 *
 * Zero out the ERI_RBT_TREE_FIELDS or call ERI_RBT_INIT_TREE before use.
 *
 * The key has to be the first field or the node to allow casting.
 * The order of all other fields are irrelevant.
 *
 * Bit fileds of ERI_RBT_NODE_FIELDS are at the beginning.
 */

#define ERI_RBT_INIT_TREE(pfx, tree) \
  do {									\
    typeof (tree) _tree = tree;						\
    _tree->ERI_PASTE (pfx, _rbt_root) = 0;				\
    _tree->ERI_PASTE (pfx, _rbt_size) = 0;				\
   } while (0)
#define ERI_RBT_TREE_FIELDS(pfx, node_type) \
  node_type *ERI_PASTE (pfx, _rbt_root);				\
  uint64_t ERI_PASTE (pfx, _rbt_size);
#define ERI_RBT_NODE_FIELDS(pfx, node_type) \
  uint8_t ERI_PASTE (pfx, _rbt_color) : 1;				\
  node_type *ERI_PASTE (pfx, _rbt_parent),				\
  *ERI_PASTE (pfx, _rbt_left), *ERI_PASTE (pfx, _rbt_right);

#define ERI_RBT_EQ	1
#define ERI_RBT_LT	2 /* largest element less than */
#define ERI_RBT_GT	4 /* smallest element greater than */

#define ERI_RBT_LTE	(ERI_RBT_LT | ERI_RBT_EQ)
#define ERI_RBT_GTE	(ERI_RBT_GT | ERI_RBT_EQ)

#define ERI_DECLARE_RBTREE(attr, pfx, tree_type, node_type, key_type) \
attr eri_unused void ERI_PASTE (pfx, _rbt_insert) (			\
			tree_type *tree, node_type *node);		\
attr eri_unused void ERI_PASTE (pfx, _rbt_remove) (			\
			tree_type *tree, node_type *node);		\
attr eri_unused node_type *ERI_PASTE (pfx, _rbt_get) (			\
			tree_type *tree, key_type *key, int32_t flags);	\
attr eri_unused node_type *ERI_PASTE (pfx, _rbt_get_first) (		\
			tree_type *tree);				\
attr eri_unused node_type *ERI_PASTE (pfx, _rbt_get_next) (		\
			node_type *node);				\
attr eri_unused uint64_t ERI_PASTE (pfx, _rbt_get_size) (tree_type *tree);

#define ERI_DECLARE_RBTREE1(attr, pfx, tree_type, node_type) \
ERI_DECLARE_RBTREE (attr, pfx, tree_type, node_type, node_type)

#define _RBT_RED	0
#define _RBT_BLACK	1

#ifndef ERI_NO_CHECK
# define _RBT_CHECK(...) __VA_ARGS__
#else
# define _RBT_CHECK(...)
#endif

#define ERI_DEFINE_RBTREE(attr, pfx, tree_type, \
			  node_type, key_type, less_than) \
ERI_DECLARE_RBTREE (attr, pfx, tree_type, node_type, key_type)		\
									\
static eri_unused int32_t ERI_PASTE (pfx, _rbt_check_recurse) (		\
			tree_type *tree, node_type *n, node_type **v,	\
			uint64_t *size);				\
static eri_unused void ERI_PASTE (pfx, _rbt_check) (tree_type *tree);	\
									\
static int32_t								\
ERI_PASTE (pfx, _rbt_check_recurse) (tree_type *tree, node_type *n,	\
				     node_type **v, uint64_t *size)	\
{									\
  if (! n) return 0;							\
									\
  eri_assert (++*size <= tree->ERI_PASTE (pfx, _rbt_size));		\
  if (n->ERI_PASTE (pfx, _rbt_color) == _RBT_RED)			\
    {									\
      eri_assert (! n->ERI_PASTE (pfx, _rbt_left)			\
		  || n->ERI_PASTE (pfx, _rbt_left)			\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_BLACK);	\
      eri_assert (! n->ERI_PASTE (pfx, _rbt_right)			\
		|| n->ERI_PASTE (pfx, _rbt_right)			\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_BLACK);	\
    }									\
									\
  int32_t h = ERI_PASTE (pfx, _rbt_check_recurse) (tree,		\
			n->ERI_PASTE (pfx, _rbt_left), v, size);	\
  eri_assert (! *v							\
	      || less_than (tree, (key_type *) *v, (key_type *) n));	\
  v = &n;								\
  eri_assert (h == ERI_PASTE (pfx, _rbt_check_recurse) (tree,		\
			n->ERI_PASTE (pfx, _rbt_right), v, size));	\
  eri_assert (*v == n							\
	      || less_than (tree, (key_type *) n, (key_type *)*v));	\
									\
  return h + (n->ERI_PASTE (pfx, _rbt_color) == _RBT_BLACK);		\
}									\
									\
static void								\
ERI_PASTE (pfx, _rbt_check) (tree_type *tree)				\
{									\
  if (tree->ERI_PASTE (pfx, _rbt_root))					\
    eri_assert (tree->ERI_PASTE (pfx, _rbt_root)			\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_BLACK);	\
									\
  node_type *v = 0;							\
  uint64_t size = 0;							\
  ERI_PASTE (pfx, _rbt_check_recurse) (tree,				\
			tree->ERI_PASTE (pfx, _rbt_root), &v, &size);	\
}									\
									\
static inline node_type *						\
ERI_PASTE (pfx, _rbt_parent) (node_type *n)				\
{									\
  return n->ERI_PASTE (pfx, _rbt_parent);				\
}									\
									\
static inline node_type *						\
ERI_PASTE (pfx, _rbt_grandparent) (node_type *n)			\
{									\
  return ERI_PASTE (pfx, _rbt_parent) (n)				\
	   ? ERI_PASTE (pfx, _rbt_parent) (				\
			ERI_PASTE (pfx, _rbt_parent) (n)) : 0;		\
}									\
									\
static inline node_type *						\
ERI_PASTE (pfx, _rbt_sibling) (node_type *n)				\
{									\
  node_type *p = ERI_PASTE (pfx, _rbt_parent) (n);			\
  if (! p) return 0;							\
  return n == p->ERI_PASTE (pfx, _rbt_left)				\
		? p->ERI_PASTE (pfx, _rbt_right)			\
		: p->ERI_PASTE (pfx, _rbt_left);			\
}									\
									\
static inline node_type *						\
ERI_PASTE (pfx, _rbt_uncle) (node_type *n)				\
{									\
  return ERI_PASTE (pfx, _rbt_grandparent) (n)				\
	 ? ERI_PASTE (pfx, _rbt_sibling) (				\
			ERI_PASTE (pfx, _rbt_parent) (n)) : 0;		\
}									\
									\
static void								\
ERI_PASTE (pfx, _rbt_rotate_left) (tree_type *tree, node_type *n)	\
{									\
  node_type *p = ERI_PASTE (pfx, _rbt_parent) (n);			\
  node_type *nn = n->ERI_PASTE (pfx, _rbt_right);			\
  n->ERI_PASTE (pfx, _rbt_right) = nn->ERI_PASTE (pfx, _rbt_left);	\
									\
  if (nn->ERI_PASTE (pfx, _rbt_left))					\
    nn->ERI_PASTE (pfx, _rbt_left)->ERI_PASTE (pfx, _rbt_parent) = n;	\
  nn->ERI_PASTE (pfx, _rbt_parent) = p;					\
									\
  if (! p) tree->ERI_PASTE (pfx, _rbt_root) = nn;			\
  else if (n == p->ERI_PASTE (pfx, _rbt_left))				\
    p->ERI_PASTE (pfx, _rbt_left) = nn;					\
  else p->ERI_PASTE (pfx, _rbt_right) = nn;				\
									\
  nn->ERI_PASTE (pfx, _rbt_left) = n;					\
  n->ERI_PASTE (pfx, _rbt_parent) = nn;					\
}									\
									\
static void								\
ERI_PASTE (pfx, _rbt_rotate_right) (tree_type *tree, node_type *n)	\
{									\
  node_type *p = ERI_PASTE (pfx, _rbt_parent) (n);			\
  node_type *nn = n->ERI_PASTE (pfx, _rbt_left);			\
  n->ERI_PASTE (pfx, _rbt_left) = nn->ERI_PASTE (pfx, _rbt_right);	\
									\
  if (nn->ERI_PASTE (pfx, _rbt_right))					\
    nn->ERI_PASTE (pfx, _rbt_right)->ERI_PASTE (pfx, _rbt_parent) = n;	\
  nn->ERI_PASTE (pfx, _rbt_parent) = p;					\
									\
  if (! p) tree->ERI_PASTE (pfx, _rbt_root) = nn;			\
  else if (n == p->ERI_PASTE (pfx, _rbt_right))				\
    p->ERI_PASTE (pfx, _rbt_right) = nn;				\
  else p->ERI_PASTE (pfx, _rbt_left) = nn;				\
									\
  nn->ERI_PASTE (pfx, _rbt_right) = n;					\
  n->ERI_PASTE (pfx, _rbt_parent) = nn;					\
}									\
									\
static void								\
ERI_PASTE (pfx, _rbt_insert_recurse) (tree_type *tree, node_type *r,	\
				      node_type *n)			\
{									\
  if (less_than (tree, (key_type *) n, (key_type *) r))			\
    {									\
      if (r->ERI_PASTE (pfx, _rbt_left))				\
	ERI_PASTE (pfx, _rbt_insert_recurse) (tree,			\
				r->ERI_PASTE (pfx, _rbt_left), n);	\
      else								\
	{								\
	  r->ERI_PASTE (pfx, _rbt_left) = n;				\
	  n->ERI_PASTE (pfx, _rbt_parent) = r;				\
	}								\
    }									\
  else if (less_than (tree, (key_type *) r, (key_type *) n))		\
    {									\
      if (r->ERI_PASTE (pfx, _rbt_right))				\
	ERI_PASTE (pfx, _rbt_insert_recurse) (tree,			\
				r->ERI_PASTE (pfx, _rbt_right), n);	\
      else								\
	{								\
	  r->ERI_PASTE (pfx, _rbt_right) = n;				\
	  n->ERI_PASTE (pfx, _rbt_parent) = r;				\
	}								\
    }									\
  else eri_assert_unreachable ();					\
}									\
									\
static void								\
ERI_PASTE (pfx, _rbt_insert_repair) (tree_type *tree, node_type *n)	\
{									\
  if (! ERI_PASTE (pfx, _rbt_parent) (n))				\
    n->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;			\
  else if (ERI_PASTE (pfx, _rbt_parent) (n)				\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_RED)	\
    {									\
      if (ERI_PASTE (pfx, _rbt_uncle) (n)				\
	  && ERI_PASTE (pfx, _rbt_uncle) (n)				\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_RED)	\
	{								\
	  ERI_PASTE (pfx, _rbt_parent) (n)				\
			->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;	\
	  ERI_PASTE (pfx, _rbt_uncle) (n)				\
			->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;	\
	  ERI_PASTE (pfx, _rbt_grandparent) (n)				\
			->ERI_PASTE (pfx, _rbt_color) = _RBT_RED;	\
	  ERI_PASTE (pfx, _rbt_insert_repair) (tree,			\
			ERI_PASTE (pfx, _rbt_grandparent) (n));		\
	}								\
      else								\
	{								\
	  node_type *p = ERI_PASTE (pfx, _rbt_parent) (n);		\
	  node_type *g = ERI_PASTE (pfx, _rbt_grandparent) (n);		\
									\
	  if (p == g->ERI_PASTE (pfx, _rbt_left))			\
	    {								\
	      if (n == p->ERI_PASTE (pfx, _rbt_right))			\
		{							\
		  ERI_PASTE (pfx, _rbt_rotate_left) (0, p);		\
		  n = n->ERI_PASTE (pfx, _rbt_left);			\
		}							\
	      ERI_PASTE (pfx, _rbt_rotate_right) (tree, g);		\
	    }								\
	  else								\
	    {								\
	      if (n == p->ERI_PASTE (pfx, _rbt_left))			\
		{							\
		  ERI_PASTE (pfx, _rbt_rotate_right) (0, p);		\
		  n = n->ERI_PASTE (pfx, _rbt_right);			\
		}							\
	      ERI_PASTE (pfx, _rbt_rotate_left) (tree, g);		\
	    }								\
	  ERI_PASTE (pfx, _rbt_parent) (n)				\
			->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;	\
	  g->ERI_PASTE (pfx, _rbt_color) = _RBT_RED;			\
	}								\
    }									\
}									\
									\
attr void								\
ERI_PASTE (pfx, _rbt_insert) (tree_type *tree, node_type *node)		\
{									\
  node->ERI_PASTE (pfx, _rbt_color) = _RBT_RED;				\
  node->ERI_PASTE (pfx, _rbt_parent)					\
		= node->ERI_PASTE (pfx, _rbt_left)			\
		= node->ERI_PASTE (pfx, _rbt_right) = 0;		\
									\
  if (! tree->ERI_PASTE (pfx, _rbt_root))				\
    tree->ERI_PASTE (pfx, _rbt_root) = node;				\
  else ERI_PASTE (pfx, _rbt_insert_recurse) (tree,			\
			tree->ERI_PASTE (pfx, _rbt_root), node);	\
									\
  ERI_PASTE (pfx, _rbt_insert_repair) (tree, node);			\
  ++tree->ERI_PASTE (pfx, _rbt_size);					\
									\
  _RBT_CHECK (ERI_PASTE (pfx, _rbt_check) (tree));			\
}									\
									\
static void								\
ERI_PASTE (pfx, _rbt_remove_repair) (tree_type *tree, node_type *p,	\
				     node_type *n)			\
{									\
  if (! p) return;							\
									\
  node_type *s = n == p->ERI_PASTE (pfx, _rbt_left)			\
		      ? p->ERI_PASTE (pfx, _rbt_right)			\
		      : p->ERI_PASTE (pfx, _rbt_left);			\
  if (s->ERI_PASTE (pfx, _rbt_color) == _RBT_RED)			\
    {									\
      p->ERI_PASTE (pfx, _rbt_color) = _RBT_RED;			\
      s->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;			\
      if (n == p->ERI_PASTE (pfx, _rbt_left))				\
	ERI_PASTE (pfx, _rbt_rotate_left) (tree, p);			\
      else								\
	ERI_PASTE (pfx, _rbt_rotate_right) (tree, p);			\
      s = n == p->ERI_PASTE (pfx, _rbt_left)				\
		? p->ERI_PASTE (pfx, _rbt_right)			\
		: p->ERI_PASTE (pfx, _rbt_left);			\
    }									\
									\
  if ((! s->ERI_PASTE (pfx, _rbt_left)					\
       || s->ERI_PASTE (pfx, _rbt_left)					\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_BLACK)	\
      && (! s->ERI_PASTE (pfx, _rbt_right)				\
	  || s->ERI_PASTE (pfx, _rbt_right)				\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_BLACK))	\
    {									\
      s->ERI_PASTE (pfx, _rbt_color) = _RBT_RED;			\
      if (p->ERI_PASTE (pfx, _rbt_color) == _RBT_BLACK)			\
	ERI_PASTE (pfx, _rbt_remove_repair) (tree,			\
				ERI_PASTE (pfx, _rbt_parent) (p), p);	\
      else								\
	p->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;			\
    }									\
  else									\
    {									\
      if (n == p->ERI_PASTE (pfx, _rbt_left)				\
	  && (s->ERI_PASTE (pfx, _rbt_left)				\
	      && s->ERI_PASTE (pfx, _rbt_left)				\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_RED)	\
	  && (! s->ERI_PASTE (pfx, _rbt_right)				\
	      || s->ERI_PASTE (pfx, _rbt_right)				\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_BLACK))	\
	{								\
	  s->ERI_PASTE (pfx, _rbt_color) = _RBT_RED;			\
	  s->ERI_PASTE (pfx, _rbt_left)					\
			->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;	\
	  ERI_PASTE (pfx, _rbt_rotate_right) (0, s);			\
	  s = p->ERI_PASTE (pfx, _rbt_right);				\
	}								\
      else if (n == p->ERI_PASTE (pfx, _rbt_right)			\
	       && (! s->ERI_PASTE (pfx, _rbt_left)			\
		   || s->ERI_PASTE (pfx, _rbt_left)			\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_BLACK)	\
	       && (s->ERI_PASTE (pfx, _rbt_right)			\
		   && s->ERI_PASTE (pfx, _rbt_right)			\
			->ERI_PASTE (pfx, _rbt_color) == _RBT_RED))	\
	{								\
	  s->ERI_PASTE (pfx, _rbt_color) = _RBT_RED;			\
	  s->ERI_PASTE (pfx, _rbt_right)				\
			->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;	\
	  ERI_PASTE (pfx, _rbt_rotate_left) (0, s);			\
	  s = p->ERI_PASTE (pfx, _rbt_left);				\
	}								\
									\
      s->ERI_PASTE (pfx, _rbt_color) = p->ERI_PASTE (pfx, _rbt_color);	\
      p->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;			\
									\
      if (n == p->ERI_PASTE (pfx, _rbt_left))				\
	{								\
	  s->ERI_PASTE (pfx, _rbt_right)				\
			->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;	\
	  ERI_PASTE (pfx, _rbt_rotate_left) (tree, p);			\
	}								\
      else								\
	{								\
	  s->ERI_PASTE (pfx, _rbt_left)					\
			->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;	\
	  ERI_PASTE (pfx, _rbt_rotate_right) (tree, p);			\
	}								\
    }									\
}									\
									\
static void								\
ERI_PASTE (pfx, _rbt_remove_one_child) (tree_type *tree, node_type *n)	\
{									\
  node_type *c = ! n->ERI_PASTE (pfx, _rbt_right)			\
			? n->ERI_PASTE (pfx, _rbt_left)			\
			: n->ERI_PASTE (pfx, _rbt_right);		\
									\
  if (c)								\
    c->ERI_PASTE (pfx, _rbt_parent) = ERI_PASTE (pfx, _rbt_parent) (n);	\
  if (! ERI_PASTE (pfx, _rbt_parent) (n))				\
    tree->ERI_PASTE (pfx, _rbt_root) = c;				\
  else if (n == ERI_PASTE (pfx, _rbt_parent) (n)			\
					->ERI_PASTE (pfx, _rbt_left))	\
    ERI_PASTE (pfx, _rbt_parent) (n)->ERI_PASTE (pfx, _rbt_left) = c;	\
  else									\
    ERI_PASTE (pfx, _rbt_parent) (n)->ERI_PASTE (pfx, _rbt_right) = c;	\
									\
  if (n->ERI_PASTE (pfx, _rbt_color) == _RBT_BLACK)			\
    {									\
      if (c && c->ERI_PASTE (pfx, _rbt_color) == _RBT_RED)		\
	c->ERI_PASTE (pfx, _rbt_color) = _RBT_BLACK;			\
      else								\
	ERI_PASTE (pfx, _rbt_remove_repair) (tree,			\
				ERI_PASTE (pfx, _rbt_parent) (n), c);	\
    }									\
}									\
									\
attr void								\
ERI_PASTE (pfx, _rbt_remove) (tree_type *tree, node_type *node)		\
{									\
  if (node->ERI_PASTE (pfx, _rbt_left)					\
      && node->ERI_PASTE (pfx, _rbt_right))				\
    {									\
      node_type *m = node->ERI_PASTE (pfx, _rbt_left);			\
      while (m->ERI_PASTE (pfx, _rbt_right))				\
	m = m->ERI_PASTE (pfx, _rbt_right);				\
      ERI_PASTE (pfx, _rbt_remove_one_child) (tree, m);			\
									\
      m->ERI_PASTE (pfx, _rbt_parent)					\
				= ERI_PASTE (pfx, _rbt_parent) (node);	\
      m->ERI_PASTE (pfx, _rbt_left)					\
				= node->ERI_PASTE (pfx, _rbt_left);	\
      m->ERI_PASTE (pfx, _rbt_right)					\
				= node->ERI_PASTE (pfx, _rbt_right);	\
      m->ERI_PASTE (pfx, _rbt_color)					\
				= node->ERI_PASTE (pfx, _rbt_color);	\
									\
      if (! ERI_PASTE (pfx, _rbt_parent) (m))				\
	tree->ERI_PASTE (pfx, _rbt_root) = m;				\
      else if (node == ERI_PASTE (pfx, _rbt_parent) (m)			\
					->ERI_PASTE (pfx, _rbt_left))	\
	ERI_PASTE (pfx, _rbt_parent) (m)				\
				->ERI_PASTE (pfx, _rbt_left) = m;	\
      else								\
	ERI_PASTE (pfx, _rbt_parent) (m)				\
				->ERI_PASTE (pfx, _rbt_right) = m;	\
									\
      if (m->ERI_PASTE (pfx, _rbt_left))				\
	m->ERI_PASTE (pfx, _rbt_left)					\
				->ERI_PASTE (pfx, _rbt_parent) = m;	\
      if (m->ERI_PASTE (pfx, _rbt_right))				\
	m->ERI_PASTE (pfx, _rbt_right)					\
				->ERI_PASTE (pfx, _rbt_parent) = m;	\
    }									\
  else ERI_PASTE (pfx, _rbt_remove_one_child) (tree, node);		\
									\
  --tree->ERI_PASTE (pfx, _rbt_size);					\
  _RBT_CHECK (ERI_PASTE (pfx, _rbt_check) (tree));			\
}									\
									\
attr node_type *							\
ERI_PASTE (pfx, _rbt_get) (tree_type *tree,				\
			    key_type *key, int32_t flags)		\
{									\
  eri_assert (! (flags & ERI_RBT_LT) || ! (flags & ERI_RBT_GT));	\
  node_type *r = tree->ERI_PASTE (pfx, _rbt_root);			\
  node_type *v = 0;							\
  while (r)								\
    {									\
      if (less_than (tree, (key_type *) r, key))			\
	{								\
	  if ((flags & ~ERI_RBT_EQ) == ERI_RBT_LT) v = r;		\
	  r = r->ERI_PASTE (pfx, _rbt_right);				\
	}								\
      else if (less_than (tree, key, (key_type *) (r)))			\
	{								\
	  if ((flags & ~ERI_RBT_EQ) == ERI_RBT_GT) v = r;		\
	  r = r->ERI_PASTE (pfx, _rbt_left);				\
	}								\
      else								\
	{								\
	  if (flags & ERI_RBT_EQ) return r;				\
	  else if (flags == ERI_RBT_LT)					\
	    r = r->ERI_PASTE (pfx, _rbt_left);				\
	  else if (flags == ERI_RBT_GT)					\
	    r = r->ERI_PASTE (pfx, _rbt_right);				\
	  else eri_assert_unreachable ();				\
	}								\
    }									\
  return v;								\
}									\
									\
static node_type *							\
ERI_PASTE (pfx, _rbt_get_min) (node_type *n)				\
{									\
  while (n->ERI_PASTE (pfx, _rbt_left))					\
    n = n->ERI_PASTE (pfx, _rbt_left);					\
  return n;								\
}									\
									\
attr node_type *							\
ERI_PASTE (pfx, _rbt_get_first) (tree_type *tree)			\
{									\
  return tree->ERI_PASTE (pfx, _rbt_root)				\
		? ERI_PASTE (pfx, _rbt_get_min) (			\
				tree->ERI_PASTE (pfx, _rbt_root)) : 0;	\
}									\
									\
attr node_type *							\
ERI_PASTE (pfx, _rbt_get_next) (node_type *node)			\
{									\
  if (node->ERI_PASTE (pfx, _rbt_right))				\
    return ERI_PASTE (pfx, _rbt_get_min) (				\
				node->ERI_PASTE (pfx, _rbt_right));	\
									\
  node_type *n = node;							\
  while (ERI_PASTE (pfx, _rbt_parent) (n)				\
	 && n == ERI_PASTE (pfx, _rbt_parent) (n)			\
				->ERI_PASTE (pfx, _rbt_right))		\
    n = ERI_PASTE (pfx, _rbt_parent) (n);				\
  return ERI_PASTE (pfx, _rbt_parent) (n);				\
}									\
									\
attr uint64_t								\
ERI_PASTE (pfx, _rbt_get_size) (tree_type *tree)			\
{									\
  return tree->ERI_PASTE (pfx, _rbt_size);				\
}

#define ERI_DEFINE_RBTREE1(attr, pfx, tree_type, node_type, less_than) \
ERI_DEFINE_RBTREE (attr, pfx, tree_type, node_type, node_type, less_than)

#define ERI_RBT_FOREACH(pfx, tree, iter) \
  for (iter = ERI_PASTE (pfx, _rbt_get_first) (tree);			\
       iter; iter = ERI_PASTE (pfx, _rbt_get_next) (iter))
#define ERI_RBT_FOREACH_SAFE(pfx, tree, iter, next) \
  for (iter = ERI_PASTE (pfx, _rbt_get_first) (tree);			\
       iter && ({ next = ERI_PASTE (pfx, _rbt_get_next) (iter); 1; });	\
       iter = next)

#define eri_less_than(x, a, b) (*(a) < *(b))

#endif
