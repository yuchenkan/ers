#include "analysis.h"

#include "lib/util.h"
#include "lib/printf.h"
#include "lib/lock.h"
#include "lib/list.h"
#include "lib/rbtree.h"

struct addr
{
  unsigned long addr;
  unsigned long size;

  ERI_RBT_NODE_FIELDS (addr, struct addr)
};

struct addrs
{
  ERI_RBT_TREE_FIELDS (addr, struct addr)
};

ERI_DEFINE_RBTREE (static, addr, struct addrs, struct addr, unsigned long, eri_less_than)

#define BLOCK_ACQ	0
#define BLOCK_REL	1
#define BLOCK_FORK	2

struct block
{
  char type;

  struct block *prev;
  struct block *next;
  struct block *child;

  unsigned long var;
  unsigned long ver;

  struct addrs reads;
  struct addrs writes;
};

struct eri_analysis
{
  struct eri_mtpool *pool;

  struct block *root;
};

struct eri_analysis_thread
{
  struct eri_analysis *analysis;

  char silence;

  struct block *cur;
};

struct eri_analysis *
eri_analysis_create (struct eri_mtpool *pool)
{
  struct eri_analysis *al = eri_assert_mtcalloc (pool, sizeof *al);
  al->pool = pool;
  return al;
}

static void
free_addrs (struct eri_mtpool *pool, struct addrs *addrs)
{
  struct addr *a, *na;
  ERI_RBT_FOREACH_SAFE (addr, addrs, a, na)
    {
      addr_rbt_remove (addrs, a);
      eri_assert_mtfree (pool, a);
    }
}

static void
delete_block_recurse (struct eri_mtpool *pool, struct block *block)
{
  if (block->next) delete_block_recurse (pool, block->next);
  if (block->child) delete_block_recurse (pool, block->child);

  free_addrs (pool, &block->reads);
  free_addrs (pool, &block->writes);

  eri_assert_mtfree (pool, block);
}

void
eri_analysis_delete (struct eri_analysis *analysis)
{
  // TODO

  struct eri_mtpool *pool = analysis->pool;

  if (analysis->root)
    delete_block_recurse (pool, analysis->root);

  eri_assert_mtfree (pool, analysis);
}

static void
create_block (struct eri_analysis_thread *th, char type,
	      struct block *parent)
{
  if (parent) eri_assert (! th->cur);

  struct block *b = eri_assert_mtcalloc (th->analysis->pool, sizeof *b);
  b->type = type;

  b->prev = parent ? : th->cur;
  if (parent) parent->child = b;
  else if (th->cur) th->cur->next = b;
  else th->analysis->root = b;

  th->cur = b;
}

struct eri_analysis_thread *
eri_analysis_create_thread (struct eri_analysis *analysis,
			    struct eri_analysis_thread *parent)
{
  struct eri_analysis_thread *th = eri_assert_mtcalloc (analysis->pool, sizeof *th);
  th->analysis = analysis;
  th->silence = parent ? parent->silence : 0;

  if (parent) create_block (parent, BLOCK_FORK, 0);
  create_block (th, BLOCK_FORK, parent ? parent->cur : 0);

  return th;
}

void
eri_analysis_delete_thread (struct eri_analysis_thread *th)
{
  eri_assert_mtfree (th->analysis->pool, th);
}

static void
addrs_insert (struct eri_mtpool *pool, struct addrs *addrs,
	      unsigned long addr, unsigned long size)
{
  eri_assert (size);

  struct addr *le = addr_rbt_get (addrs, &addr, ERI_RBT_LT | ERI_RBT_EQ);
  struct addr *g = addr_rbt_get (addrs, &addr, ERI_RBT_GT);

  if (le && g) eri_assert (le->addr + le->size < g->addr);

  struct addr *a = 0;
  if (le && le->addr + le->size >= addr)
    {
      addr_rbt_remove (addrs, le);
      size = eri_max (addr + size, le->addr + le->size) - le->addr;
      addr = le->addr;

      a = le;
    }

  if (g && g->addr <= addr + size)
    {
      addr_rbt_remove (addrs, g);
      size = eri_max (addr + size, g->addr + g->size) - addr;

      if (! a) a = g;
      else eri_assert_mtfree (pool, g);
    }

  if (! a) a = eri_assert_mtmalloc (pool, sizeof *a);

  a->addr = addr;
  a->size = size;
  addr_rbt_insert (addrs, a);
}

void
eri_analysis_record (struct eri_analysis_thread *th,
		     struct eri_vex_brk_desc *desc)
{
  eri_assert (desc->type != ERI_VEX_BRK_PRE_EXEC);

  struct eri_mtpool *pool = th->analysis->pool;

  if (! th->silence)
    {
      addrs_insert (pool, &th->cur->reads, desc->rip, desc->length);
      size_t i;
      for (i = 0; i < desc->reads->n; ++i)
	addrs_insert (pool, &th->cur->reads,
		      desc->reads->addrs[i], desc->reads->sizes[i]);
      for (i = 0; i < desc->writes->n; ++i)
	addrs_insert (pool, &th->cur->writes,
		      desc->writes->addrs[i], desc->writes->sizes[i]);
    }
}

void
eri_analysis_silence (struct eri_analysis_thread *th, char enter)
{
  eri_assert (th->silence ^ enter);
  th->silence = enter;
}

void
eri_analysis_sync (struct eri_analysis_thread *th, char acq,
		   unsigned long var, unsigned long ver)
{
  create_block (th, acq ? BLOCK_ACQ : BLOCK_REL, 0);
  th->cur->var = var;
  th->cur->ver = ver;
}
