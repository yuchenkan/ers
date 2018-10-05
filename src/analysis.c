#include "analysis.h"

#include "lib/util.h"
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

struct block
{
  char sync_acq;
  unsigned long sync_var;
  unsigned long sync_ver;

  struct addrs reads;
  struct addrs writes;

  ERI_LST_NODE_FIELDS (block)
};

struct thread_blocks
{
  unsigned long id;
  ERI_RBT_NODE_FIELDS (thread_blocks, struct thread_blocks)

  ERI_LST_LIST_FIELDS (block)
};

ERI_DEFINE_LIST (static, block, struct thread_blocks, struct block)

struct eri_analysis
{
  struct eri_mtpool *pool;

  int thread_blocks_lock;
  ERI_RBT_TREE_FIELDS (thread_blocks, struct thread_blocks)
};

ERI_DEFINE_RBTREE (static, thread_blocks, struct eri_analysis,
		   struct thread_blocks, unsigned long, eri_less_than)

struct eri_analysis_thread
{
  struct eri_analysis *analysis;

  char silence;

  struct block *cur;
  struct thread_blocks *blocks;
};

struct eri_analysis *
eri_analysis_create (struct eri_mtpool *pool)
{
  struct eri_analysis *al = eri_assert_mtcalloc (pool, sizeof *al);
  al->pool = pool;
  return al;
}

void
eri_analysis_delete (struct eri_analysis *analysis)
{
  // TODO

  struct eri_mtpool *pool = analysis->pool;

  struct thread_blocks *t, *nt;
  ERI_RBT_FOREACH_SAFE (thread_blocks, analysis, t, nt)
    {
      thread_blocks_rbt_remove (analysis, t);

      struct block *b, *nb;
      ERI_LST_FOREACH_SAFE (block, t, b, nb)
	{
	  struct addr *a, *na;
	  ERI_RBT_FOREACH_SAFE (addr, &b->reads, a, na)
	    {
	      addr_rbt_remove (&b->reads, a);
	      eri_assert_mtfree (pool, a);
	    }
	  ERI_RBT_FOREACH_SAFE (addr, &b->writes, a, na)
	    {
	      addr_rbt_remove (&b->writes, a);
	      eri_assert_mtfree (pool, a);
	    }

	  eri_assert_mtfree (pool, b);
	}

      eri_assert_mtfree (pool, t);
    }

  eri_assert_mtfree (pool, analysis);
}

struct eri_analysis_thread *
eri_analysis_create_thread (struct eri_analysis *analysis, unsigned long id)
{
  struct eri_analysis_thread *th = eri_assert_mtcalloc (analysis->pool, sizeof *th);
  th->analysis = analysis;

  th->blocks = eri_assert_mtmalloc (analysis->pool, sizeof *th->blocks);
  th->blocks->id = id;
  ERI_LST_INIT_LIST (block, th->blocks);

  eri_lock (&analysis->thread_blocks_lock);
  thread_blocks_rbt_insert (analysis, th->blocks);
  eri_unlock (&analysis->thread_blocks_lock);

  th->cur = eri_assert_mtcalloc (analysis->pool, sizeof *th->cur);
  block_lst_append (th->blocks, th->cur);

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
  th->cur = eri_assert_mtcalloc (th->analysis->pool, sizeof *th->cur);
  block_lst_append (th->blocks, th->cur);

  th->cur->sync_acq = acq;
  th->cur->sync_var = var;
  th->cur->sync_ver = ver;
}
