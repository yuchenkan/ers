#include <stdarg.h>

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
  unsigned long watch;

  ERI_RBT_TREE_FIELDS (addr, struct addr)
};

ERI_DEFINE_RBTREE (static, addr, struct addrs, struct addr, unsigned long, eri_less_than)

struct block
{
  unsigned long refs;

  struct eri_analysis_thread *thread;
  unsigned long thread_name;
  unsigned long insts_start;
  unsigned long insts_end;

  struct block *next;

  char release;
  unsigned long var;
  unsigned long ver;

  struct addrs reads;
  struct addrs writes;

  unsigned long watch;
};

struct eri_analysis
{
  struct eri_mtpool *pool;
  int *printf_lock;

  int block_lock;
  struct block block_end;

  unsigned long watch;
};

struct async
{
  struct block *block;

  ERI_LST_NODE_FIELDS (async)
};

struct eri_analysis_thread
{
  unsigned long name;

  struct eri_analysis *analysis;

  unsigned long total_insts;

  char silence;

  struct block *head;
  struct block *cur;

  ERI_LST_LIST_FIELDS (async)
};

ERI_DEFINE_LIST (static, async, struct eri_analysis_thread, struct async)

struct eri_analysis *
eri_analysis_create (struct eri_mtpool *pool, int *printf_lock)
{
  struct eri_analysis *al = eri_assert_mtcalloc (pool, sizeof *al);
  al->pool = pool;
  al->printf_lock = printf_lock;
  al->block_end.refs = 1;
  // al->watch = 0x7fffd1315920;
  return al;
}

void
eri_analysis_delete (struct eri_analysis *analysis)
{
  eri_assert_printf ("delete analysis\n");

  eri_assert (analysis->block_end.refs == 1);
  eri_assert_mtfree (analysis->pool, analysis);
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
do_confirm (struct block *ab, struct addrs *as, struct block *bb, struct addrs *bs)
{
  struct eri_analysis *al = ab->thread->analysis;

  struct addr *a;
  ERI_RBT_FOREACH (addr, as, a)
    {
      struct addr *ble = addr_rbt_get (bs, &a->addr, ERI_RBT_LT | ERI_RBT_EQ);
      struct addr *bg = addr_rbt_get (bs, &a->addr, ERI_RBT_GT);

      if (ble && ble->addr + ble->size > a->addr)
	eri_assert_lprintf (al->printf_lock, "conflict %s %lu %lu %lu with %s %lu %lu %lu: %lx %lu\n",
			    &ab->reads == as ? "read" : "write", ab->thread_name, ab->insts_start, ab->insts_end,
			    &bb->reads == bs ? "read" : "write", bb->thread_name, bb->insts_start, bb->insts_end,
			    a->addr, eri_min (a->addr + a->size, ble->addr + ble->size) - a->addr);
      if (bg && a->addr + a->size > bg->addr)
	eri_assert_lprintf (al->printf_lock, "conflict %s %lu %lu %lu with %s %lu %lu %lu: %lx %lu\n",
			    &ab->reads == as ? "read" : "write", ab->thread_name, ab->insts_start, ab->insts_end,
			    &bb->reads == bs ? "read" : "write", bb->thread_name, bb->insts_start, bb->insts_end,
			    bg->addr, eri_min (a->addr + a->size, bg->addr + bg->size) - bg->addr);
    }
}

static void
confirm (struct block *a, struct block *b)
{
  struct eri_analysis *al = a->thread->analysis;

#ifndef NO_CHECK
  eri_assert_lprintf (al->printf_lock, "confirm %lu %lu %lu %lu\n",
		      addr_rbt_get_size (&a->reads),
		      addr_rbt_get_size (&a->writes),
		      addr_rbt_get_size (&b->reads),
		      addr_rbt_get_size (&b->writes));
#endif

  if ((a->reads.watch && b->writes.watch)
      || (a->writes.watch && b->reads.watch))
    eri_assert_lprintf (al->printf_lock, "watch block confirm %x %lx\n", a, b);

  do_confirm (a, &a->reads, b, &b->writes);
  do_confirm (a, &a->writes, b, &b->reads);
}

#define block_inc(b) do { ++(b)->refs; } while (0)

#define block_assign(th, v, b) \
  do {											\
    struct eri_analysis_thread *__th = th;						\
    struct block **__vp = &(v);								\
    struct block *__b = b;								\
    struct block *__t = *__vp;								\
    *__vp = __b;									\
    if (__b) block_inc (__b);								\
    if (__t) block_dec (__th, __t);							\
  } while (0)

static void
block_dec (struct eri_analysis_thread *th, struct block *b)
{
  struct eri_analysis *al = th->analysis;

  if (--b->refs == 0)
    {
      if (b->watch)
	eri_assert_lprintf (al->printf_lock, "watch block free %lu %lx\n", th->name, b);

      if (b->thread) b->thread->head = b->next;
      block_assign (th, b->next, 0);

      free_addrs (al->pool, &b->reads);
      free_addrs (al->pool, &b->writes);
      eri_assert_mtfree (al->pool, b);
    }
}

static void
asyncs_sync (struct eri_analysis_thread *th, unsigned long var, unsigned long ver)
{
  struct eri_analysis *al = th->analysis;

  struct async *a, *na;
  ERI_LST_FOREACH_SAFE (async, th, a, na)
    {
      struct block *b = a->block;
      struct block *watch = 0;
      while (b->next)
	{
	  if (b->watch) watch = b;

	  struct block *t = b->next;
	  if (b->release && b->var == var && b->ver <= ver)
	    {
	      char brk = b->ver == ver;
	      block_assign (th, a->block, b->next);
	      if (watch)
		{
		  eri_assert_lprintf (al->printf_lock,
				      "watch block sync %lu %lx %lx %lu\n",
				      th->name, watch, var, ver);
		  watch = 0;
		}
	      if (brk) break;
	    }
	  b = t;
	}

      if (a->block == &al->block_end)
	{
	  async_lst_remove (th, a);
	  block_assign (th, a->block, 0);
	  eri_assert_mtfree (al->pool, a);
	}
    }
}

static void
asyncs_confirm (struct eri_analysis_thread *th)
{
  eri_assert (th->cur != &th->analysis->block_end);

  if (! addr_rbt_get_size (&th->cur->reads)
      && ! addr_rbt_get_size (&th->cur->writes))
    return;

  struct async *a;
  ERI_LST_FOREACH (async, th, a)
    {
      struct block *b;
      for (b = a->block; b->next; b = b->next)
	confirm (th->cur, b);
    }
}

static void
alloc_async (struct eri_analysis_thread *th, struct block *b)
{
  struct async *a = eri_assert_mtcalloc (th->analysis->pool, sizeof *a);
  block_assign (th, a->block, b);
  async_lst_append (th, a);
}

static void
asyncs_clone (struct eri_analysis_thread *th,
	      struct eri_analysis_thread *parent, struct block *b)
{
  struct async *a;
  ERI_LST_FOREACH (async, parent, a)
    {
      alloc_async (th, a->block);
      if (a->block->thread)
	alloc_async (a->block->thread, b);
    }

  alloc_async (th, parent->cur);
  alloc_async (parent, b);
}

static void
asyncs_end (struct eri_analysis_thread *th)
{
  struct eri_analysis *al = th->analysis;

  struct async *a, *na;
  ERI_LST_FOREACH_SAFE (async, th, a, na)
    {
      async_lst_remove (th, a);
      block_assign (th, a->block, 0);
      eri_assert_mtfree (al->pool, a);
    }
  block_assign (th, th->cur, 0);

  struct block *b;
  for (b = th->head; b != &al->block_end; b = b->next)
    b->thread = 0;
}

#define PUSH_ACQ	0
#define PUSH_REL	1
#define PUSH_PARENT	2
#define PUSH_CHILD	3
#define PUSH_END	4
#define PUSH_END_REL	5

static void
push_block (struct eri_analysis_thread *th, char type, ...)
{
  struct eri_analysis *al = th->analysis;

  struct block *b = &al->block_end;
  if (type != PUSH_END && type != PUSH_END_REL)
    {
      b = eri_assert_mtcalloc (al->pool, sizeof *b);
      b->thread = th;
      b->thread_name = th->name;
      b->insts_start = th->total_insts;
    }

  eri_assert ((! th->cur) ^ (type != PUSH_CHILD));

  va_list arg;
  va_start (arg, type);

  eri_lock (&al->block_lock);

#ifndef NO_CHECK
  eri_assert_lprintf (al->printf_lock, "push block %u\n", type);
#endif

  if (type == PUSH_REL || type == PUSH_END_REL)
    {
      th->cur->release = 1;
      th->cur->var = va_arg (arg, unsigned long);
      th->cur->ver = va_arg (arg, unsigned long);
    }
  else if (type == PUSH_CHILD)
    {
      struct eri_analysis_thread *parent = va_arg (arg, struct eri_analysis_thread *);
      if (parent) asyncs_clone (th, parent, b);

      th->head = b;
    }

  if (th->cur)
    {
      th->cur->insts_end = th->total_insts;
      asyncs_confirm (th);
    }

  if (type == PUSH_ACQ)
    {
      unsigned long var = va_arg (arg, unsigned long);
      unsigned long ver = va_arg (arg, unsigned long);

      asyncs_sync (th, var, ver);
    }

  if (th->cur) block_assign (th, th->cur->next, b);
  block_assign (th, th->cur, b);

  if (th->cur == &al->block_end) asyncs_end (th);

  eri_unlock (&al->block_lock);

  va_end (arg);
}

struct eri_analysis_thread *
eri_analysis_create_thread (struct eri_analysis *analysis,
			    struct eri_analysis_thread *parent,
			    unsigned long name)
{
  struct eri_analysis_thread *th = eri_assert_mtcalloc (analysis->pool, sizeof *th);
  th->name = name;
  th->analysis = analysis;
  th->silence = parent ? parent->silence : 0;

  ERI_LST_INIT_LIST (async, th);

  if (parent) push_block (parent, PUSH_PARENT);
  push_block (th, PUSH_CHILD, parent);

  return th;
}

void
eri_analysis_delete_thread (struct eri_analysis_thread *th)
{
  /* XXX see eri_analysis_sync_rel.  */
  if (th->cur) push_block (th, PUSH_END);

  eri_assert_mtfree (th->analysis->pool, th);
}

static void
addrs_insert (struct eri_analysis_thread *th, struct block *b,
	      struct addrs *addrs, unsigned long addr, unsigned long size)
{
  eri_assert (size);

  struct eri_analysis *al = th->analysis;

  if (al->watch
      && addr <= al->watch && addr + size > al->watch
      && ! addrs->watch)
    {
      eri_assert_lprintf (al->printf_lock, "watch block %lu %s %lx\n",
			  th->name, &b->reads == addrs ? "read" : "write", b);
      addrs->watch = al->watch;
      b->watch = 1;
    }

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
      else eri_assert_mtfree (al->pool, g);
    }

  if (! a) a = eri_assert_mtmalloc (al->pool, sizeof *a);

  a->addr = addr;
  a->size = size;
  addr_rbt_insert (addrs, a);
}

void
eri_analysis_record (struct eri_analysis_thread *th,
		     struct eri_vex_brk_desc *desc)
{
  eri_assert (desc->type != ERI_VEX_BRK_PRE_EXEC);

  th->total_insts += desc->ninsts; /* XXX */

  if (! th->silence)
    {
      eri_assert (th->cur != &th->analysis->block_end);

      addrs_insert (th, th->cur, &th->cur->reads, desc->rip, desc->length);
      size_t i;
      for (i = 0; i < desc->reads->n; ++i)
	addrs_insert (th, th->cur, &th->cur->reads,
		      desc->reads->addrs[i], desc->reads->sizes[i]);
      for (i = 0; i < desc->writes->n; ++i)
	addrs_insert (th, th->cur, &th->cur->writes,
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
eri_analysis_sync_acq (struct eri_analysis_thread *th,
		       unsigned long var, unsigned long ver)
{
  push_block (th, PUSH_ACQ, var, ver);
}

void
eri_analysis_sync_rel (struct eri_analysis_thread *th,
		       unsigned long var, unsigned long ver, unsigned long exit)
{
  /* XXX consider merge PUSH_END_REL into eri_analysis_delete_thread.  */
  push_block (th, exit ? PUSH_END_REL : PUSH_REL, var, ver);
}
