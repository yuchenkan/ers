/* vim: set ft=cpp: */

#include <lib/compiler.h>
#include <lib/cpu.h>
#include <lib/util.h>
#include <lib/lock.h>
#include <lib/atomic.h>
#include <lib/buf.h>
#include <lib/list.h>
#include <lib/rbtree.h>
#include <lib/malloc.h>

#include <common/debug.h>
#include <common/common.h>
#include <common/entry.h>

#include <analysis/analyzer.h>
#include <analysis/translate.h>

// #undef ERI_NO_CHECK

struct interval
{
  uint64_t start;
  uint64_t end;
  ERI_RBT_NODE_FIELDS (interval, struct interval)
};

struct interval_tree
{
  ERI_RBT_TREE_FIELDS (interval, struct interval)
};

ERI_DEFINE_RBTREE (static, interval, struct interval_tree,
		   struct interval, uint64_t, eri_less_than)

static eri_unused void
check_interval_tree (struct interval_tree *tree)
{
  struct interval *it = interval_rbt_get_first (tree);
  if (! it) return;

  eri_xassert (it->start < it->end, eri_info);
  uint64_t prev = it->end;

  while ((it = interval_rbt_get_next (it)))
    {
      eri_xassert (prev < it->start, eri_info);
      eri_xassert (it->start < it->end, eri_info);
      prev = it->end;
    }
}

static void
update_interval_tree (struct eri_mtpool *pool, struct interval_tree *tree,
		      uint64_t start, uint64_t end, uint8_t add,
		      void (*diff) (uint64_t, uint64_t, void *), void *args)
{
  struct interval *l;
  if (add)
    {
      l = interval_rbt_get (tree, &start, ERI_RBT_LTE);
      if (l && l->end >= end) return;
    }
  else l = interval_rbt_get (tree, &start, ERI_RBT_LT);

  struct interval *it = l ? interval_rbt_get_next (l)
			  : interval_rbt_get_first (tree);

  uint64_t add_start = start;
  if (add)
    {
      if (l && l->end >= start)
	{
	  start = l->start;
	  add_start = l->end;
	  interval_rbt_remove (tree, l);
	  eri_assert_mtfree (pool, l);
	}
    }
  else if (l && l->end > start)
    {
      diff (start, l->end, args);
      l->end = start;
    }

  while (it && it->end <= end)
    {
      if (add)
	{
	  diff (add_start, it->start, args);
	  add_start = it->end;
	}
      else diff (it->start, it->end, args);

      struct interval *tmp = interval_rbt_get_next (it);
      interval_rbt_remove (tree, it);
      eri_assert_mtfree (pool, it);
      it = tmp;
    }

  if (add)
    {
      if (it && it->start <= end)
	{
	  diff (add_start, it->start, args);
	  end = it->end;
	  interval_rbt_remove (tree, it);
	  eri_assert_mtfree (pool, it);
	}
      else if (add_start != end) diff (add_start, end, args);

      it = eri_assert_mtmalloc (pool, sizeof *it);
      it->start = start;
      it->end = end;
      interval_rbt_insert (tree, it);
    }
  else if (it && it->start < end)
    {
      diff (it->start, end, args);
      it->start = end;
    }

#ifndef ERI_NO_CHECK
  check_interval_tree (tree);
#endif
}

static void
dump_interval_tree (uint8_t t, eri_file_t log, struct interval_tree *tree)
{
  struct interval *n;
  ERI_RBT_FOREACH (interval, tree, n)
    eri_rlogn (t, log, "  %lx, %lx\n", n->start, n->end);
}

static void
empty_interval_tree (struct eri_mtpool *pool, struct interval_tree *tree)
{
  struct interval *n, *nn;
  ERI_RBT_FOREACH_SAFE (interval, tree, n, nn)
    {
      interval_rbt_remove (tree, n);
      eri_assert_mtfree (pool, n);
    }
}

struct race_access
{
  uint64_t addr;
  uint64_t size;

  uint64_t rip;
  uint64_t order;

  ERI_RBT_NODE_FIELDS (race_access, struct race_access);
};

struct race_accesses
{
  ERI_RBT_TREE_FIELDS (race_access, struct race_access);
};

static uint8_t
race_access_less_than (struct race_accesses *r,
		       struct race_access *a, struct race_access *b)
{
  return a->addr != b->addr ? a->addr < b->addr : a->order < b->order;
}

ERI_DEFINE_RBTREE1 (static, race_access, struct race_accesses,
		    struct race_access, race_access_less_than)

#define RACE_SYNC_CLONE		0
#define RACE_SYNC_KEY_VER	1

struct race_sync
{
  uint8_t type;
  union
    {
      uint64_t clone;
      struct
	{
	  uint64_t key;
	  uint64_t ver;
	} kv;
    };
};

struct race_inc
{
  uint64_t addr;
  uint64_t size;
};

struct race_ranges_insert_diff_args
{
  eri_file_t log;
  struct eri_buf *incs;
};

static void
race_ranges_insert_diff (uint64_t start, uint64_t end, void *args)
{
  struct race_ranges_insert_diff_args *a = args;;
  eri_lassert (a->log, end > start);
  struct race_inc inc = { start, end - start };
  eri_assert_buf_append (a->incs, &inc, 1);
}

static uint8_t
race_ranges_insert (eri_file_t log,
		    struct eri_mtpool *pool, struct interval_tree *ranges,
		    struct race_access *acc, struct eri_buf *incs)
{
  // eri_log (log, "%lx %lx\n", acc->addr, acc->addr + acc->size);
  uint64_t o = incs->o;
  struct race_ranges_insert_diff_args args = { log, incs };
  update_interval_tree (pool, ranges, acc->addr, acc->addr + acc->size, 1,
			race_ranges_insert_diff, &args);
  return o != incs->o;
}

static void
race_ranges_increase (eri_file_t log, struct eri_mtpool *pool,
		      struct interval_tree *ranges, struct race_inc *inc)
{
  uint64_t start = inc->addr, end = inc->addr + inc->size;
  struct interval *eq = interval_rbt_get (ranges, &start, ERI_RBT_EQ);
  if (eq)
    {
      eri_log_info (log, "%lx %lx\n", start, eq->end - start);
      eri_xassert (0, eri_info);
    }
  struct interval *lt = interval_rbt_get (ranges, &start, ERI_RBT_LT);
  struct interval *gt = lt ? interval_rbt_get_next (lt)
			   : interval_rbt_get_first (ranges);
  if (lt && lt->end == start)
    {
      start = lt->start;
      interval_rbt_remove (ranges, lt);
      eri_assert_mtfree (pool, lt);
    }
  if (gt && gt->start == end)
    {
      end = gt->end;
      interval_rbt_remove (ranges, gt);
      eri_assert_mtfree (pool, gt);
    }
  struct interval *range = eri_assert_mtmalloc (pool, sizeof *range);
  range->start = start;
  range->end = end;
  interval_rbt_insert (ranges, range);
}

static uint8_t
race_ranges_intersects (struct interval_tree *a, struct interval_tree *b)
{
  struct interval *i = interval_rbt_get_first (a);
  struct interval *j = interval_rbt_get_first (b);
  while (i && j)
    if (i->end <= j->start) i = interval_rbt_get_next (i);
    else if (j->end <= i->start) j = interval_rbt_get_next (j);
    else return 1;
  return 0;
}

struct race_area
{
  struct interval_tree reads;
  struct interval_tree writes;
  struct interval_tree prot_reads;
  struct interval_tree prot_writes;
};

struct race_inc_area
{
  struct eri_buf reads;
  struct eri_buf writes;
  struct eri_buf prot_reads;
  struct eri_buf prot_writes;
};

struct race_sealed
{
  struct race_accesses reads;
  struct race_accesses writes;
  struct race_accesses prot_reads;
  struct race_accesses prot_writes;
};

struct race_unit
{
  uint64_t id;

  struct race_unit *prev;

  struct eri_buf reads;
  struct eri_buf writes;
  struct eri_buf prot_reads;
  struct eri_buf prot_writes;

  struct race_sealed sealed;
  struct race_area inc;
};

struct race_block
{
  uint64_t id;

  uint64_t ref_count;
  uint8_t empty_end;

  struct race_block *prev; /* weak pointer */
  struct race_unit *unit;

  struct race_area pushed;
  struct race_area cur;

  struct race_inc_area inc;

  struct eri_buf afters;
  struct race_sync before;
};

struct race;

struct race_cursor
{
  struct race_block *blk;
  struct race_unit *unit;
};

struct race_ref
{
  struct race *src;
  struct race *dst;
  struct race_block *last;

  ERI_LST_NODE_FIELDS (race_ref)
};

struct race_group
{
  struct eri_mtpool *pool;
  eri_lock_t lock;

  uint64_t race_id;
  uint64_t block_id;
  uint64_t unit_id;

  uint8_t error;
};

struct race
{
  uint64_t id;

  struct race_group *group;
  eri_file_t log;

  uint64_t ref_count;
  uint8_t end;

  struct race_block *cur;

  uint64_t order;

  ERI_LST_LIST_FIELDS (race_ref);
};

ERI_DEFINE_LIST (static, race_ref, struct race, struct race_ref)

static void
race_init_group (struct race_group *group, struct eri_mtpool *pool)
{
  group->pool = pool;
  group->lock = 0;
  group->race_id = 0;
  group->block_id = 0;
  group->unit_id = 0;
  group->error = 0;
}

static struct race *
race_create (struct race_group *group, eri_file_t log)
{
  struct race *ra = eri_assert_mtmalloc (group->pool, sizeof *ra);
  ra->id = eri_atomic_fetch_inc (&group->race_id, 0);
  eri_log2 (log, "[RACE] alloc race: r%lu\n", ra->id);

  ra->group = group;
  ra->log = log;
  ra->ref_count = 1;
  ra->end = 0;
  ra->cur = 0;
  ra->order = 0;
  ERI_LST_INIT_LIST (race_ref, ra);
  return ra;
}

static void
race_init_area (struct race_area *area)
{
  ERI_RBT_INIT_TREE (interval, &area->reads);
  ERI_RBT_INIT_TREE (interval, &area->writes);
  ERI_RBT_INIT_TREE (interval, &area->prot_reads);
  ERI_RBT_INIT_TREE (interval, &area->prot_writes);
}

static void
race_add_unit (struct race *ra, struct race_block *blk)
{
  struct race_group *group = ra->group;
  struct eri_mtpool *pool = group->pool;
  struct race_unit *u = eri_assert_mtmalloc (pool, sizeof *u);
  u->id = eri_atomic_fetch_inc (&group->unit_id, 0);
  eri_log3 (ra->log, "[RACE] alloc unit: u%lu, block: b%lu\n", u->id, blk->id);
  u->prev = blk->unit;

  eri_assert_buf_mtpool_init (&u->reads, pool, 0, struct race_access);
  eri_assert_buf_mtpool_init (&u->writes, pool, 0, struct race_access);
  eri_assert_buf_mtpool_init (&u->prot_reads, pool, 0, struct race_access);
  eri_assert_buf_mtpool_init (&u->prot_writes, pool, 0, struct race_access);

  ERI_RBT_INIT_TREE (race_access, &u->sealed.reads);
  ERI_RBT_INIT_TREE (race_access, &u->sealed.writes);
  ERI_RBT_INIT_TREE (race_access, &u->sealed.prot_reads);
  ERI_RBT_INIT_TREE (race_access, &u->sealed.prot_writes);

  race_init_area (&u->inc);
  blk->unit = u;
}

static void
race_ranges_apply_inc (eri_file_t log, struct eri_mtpool *pool,
		       struct interval_tree *ranges, struct eri_buf *inc)
{
  struct race_inc *p = inc->buf;

  uint64_t i;
  for (i = 0; i < inc->o; ++i)
    race_ranges_increase (log, pool, ranges, p + i);
}

static void
race_apply_inc (eri_file_t log, struct eri_mtpool *pool,
		struct race_area *area, struct race_inc_area *inc)
{
  race_ranges_apply_inc (log, pool, &area->reads, &inc->reads);
  race_ranges_apply_inc (log, pool, &area->writes, &inc->writes);
  race_ranges_apply_inc (log, pool, &area->prot_reads, &inc->prot_reads);
  race_ranges_apply_inc (log, pool, &area->prot_writes, &inc->prot_writes);
}

static void
race_do_seal_unit (struct eri_buf *acc, struct race_accesses *s)
{
  eri_assert_buf_shrink (acc);
  struct race_access *a = acc->buf;
  uint64_t i;
  for (i = 0; i < acc->o; ++i) race_access_rbt_insert (s, a + i);
}

static void
race_dump_inc (uint8_t t, eri_file_t log, struct eri_buf *buf)
{
  struct race_inc *inc = buf->buf;
  uint64_t i;
  for (i = 0; i < buf->o; ++i)
    eri_rlogn (t, log, "  %lx %lu\n", inc[i].addr, inc[i].size);
}

static void
race_seal_unit (eri_file_t log,
	        struct eri_mtpool *pool, struct race_block *blk)
{
  struct race_unit *u = blk->unit;
  eri_log2 (log, "[RACE] block: b%lu, unit: u%lu, "
	    "reads inc %u, writes inc %u\n",
	   blk->id, u->id, blk->inc.reads.o, blk->inc.writes.o);
  uint8_t t = 3;
  eri_logn (t, log, "[RACE] reads:\n");
  race_dump_inc (t, log, &blk->inc.reads);
  eri_logn (t, log, "[RACE] writes:\n");
  race_dump_inc (t, log, &blk->inc.writes);

  race_do_seal_unit (&u->reads, &u->sealed.reads);
  race_do_seal_unit (&u->writes, &u->sealed.writes);
  race_do_seal_unit (&u->prot_reads, &u->sealed.prot_reads);
  race_do_seal_unit (&u->prot_writes, &u->sealed.prot_writes);

  race_apply_inc (log, pool, &blk->pushed, &blk->inc);
  race_apply_inc (log, pool, &blk->unit->inc, &blk->inc);

  eri_buf_release (&blk->inc.reads);
  eri_buf_release (&blk->inc.writes);
  eri_buf_release (&blk->inc.prot_reads);
  eri_buf_release (&blk->inc.prot_writes);
}

static void
race_empty_area (struct eri_mtpool *pool, struct race_area *area)
{
  empty_interval_tree (pool, &area->reads);
  empty_interval_tree (pool, &area->writes);
  empty_interval_tree (pool, &area->prot_reads);
  empty_interval_tree (pool, &area->prot_writes);
}

static void
race_add_block (struct race *ra)
{
  struct eri_mtpool *pool = ra->group->pool;
  struct race_block *blk = eri_assert_mtmalloc (pool, sizeof *blk);
  blk->id = eri_atomic_fetch_inc (&ra->group->block_id, 0);
  eri_log2 (ra->log, "[RACE] alloc block: b%lu, ref_count: %lu\n",
	    blk->id, ra->ref_count);

  blk->ref_count = ra->ref_count;
  blk->empty_end = 0;
  blk->prev = ra->cur;
  blk->unit = 0;
  race_add_unit (ra, blk);
  race_init_area (&blk->pushed);
  race_init_area (&blk->cur);

  struct race_inc_area *inc = &blk->inc;
  eri_assert_buf_mtpool_init (&inc->reads, pool, 0, struct race_inc);
  eri_assert_buf_mtpool_init (&inc->writes, pool, 0, struct race_inc);
  eri_assert_buf_mtpool_init (&inc->prot_reads, pool, 0, struct race_inc);
  eri_assert_buf_mtpool_init (&inc->prot_writes, pool, 0, struct race_inc);

  eri_assert_buf_mtpool_init (&blk->afters, pool, 1, struct race_sync);
  ra->cur = blk;
}

static void
race_hold_blocks (eri_file_t log,
		  struct race_block *first, struct race_block *last)
{
  while (1)
    {
      eri_log3 (log, "[RACE] block inc ref_count: b%lu\n", first->id);
      eri_atomic_inc (&first->ref_count, 0);
      if (first == last) break;
      first = first->prev;
    }
}

static void
race_add_ref (eri_file_t log,
	      struct race *src, struct race *dst, struct race_block *last)
{
  struct eri_mtpool *pool = src->group->pool;
  struct race_ref *ref = eri_assert_mtmalloc (pool, sizeof *ref);
  eri_log9 (log, "[RACE] alloc ref: %lx\n", ref);
  ref->src = src;
  eri_log3 (log, "[RACE] race inc ref_count: r%lu\n", dst->id);
  eri_atomic_inc (&dst->ref_count, 0);
  ref->dst = dst;
  ref->last = last;
  race_hold_blocks (log, dst->cur, last);
  race_ref_lst_append (src, ref);
}

static void
race_release_block (eri_file_t log,
		    struct eri_mtpool *pool, struct race_block *blk)
{
  eri_log3 (log, "[RACE] block dec ref_count: b%lu\n", blk->id);
  if (eri_atomic_dec_fetch (&blk->ref_count, 1)) return;

  eri_assert_buf_fini (&blk->afters);

  eri_assert_buf_fini (&blk->inc.reads);
  eri_assert_buf_fini (&blk->inc.writes);
  eri_assert_buf_fini (&blk->inc.prot_reads);
  eri_assert_buf_fini (&blk->inc.prot_writes);

  race_empty_area (pool, &blk->pushed);

  struct race_unit *u = blk->unit;
  while (u)
    {
      struct race_unit *t = u->prev;
      eri_log3 (log, "[RACE] free unit: %lu\n", u->id);
      eri_assert_buf_fini (&u->reads);
      eri_assert_buf_fini (&u->writes);
      eri_assert_buf_fini (&u->prot_reads);
      eri_assert_buf_fini (&u->prot_writes);
      eri_assert_mtfree (pool, u);
      u = t;
    }
  eri_log2 (log, "[RACE] free block: b%lu\n", blk->id);

  eri_assert_mtfree (pool, blk);
}

static void
race_release (eri_file_t log, struct race *ra)
{
  eri_log3 (log, "[RACE] race dec ref_count: r%lu\n", ra->id);
  if (eri_atomic_dec_fetch (&ra->ref_count, 1)) return;

  eri_log2 (log, "[RACE] free race: r%lu\n", ra->id);
  eri_assert_mtfree (ra->group->pool, ra);
}

static void
race_free_ref (eri_file_t log,
	       struct eri_mtpool *pool, struct race_ref *ref)
{
  eri_log9 (log, "[RACE] free ref: %lx\n", ref);
  eri_assert_mtfree (pool, ref);
}

#define ACCESS_NUM	(ERI_ACCESS_END - ERI_ACCESS_START)

#define race_get_type(t, p) \
  ({ uint8_t _t = t; typeof (p) _p = p;					\
     _t == ERI_ACCESS_READ ? &_p->reads					\
	: (_t == ERI_ACCESS_WRITE ? &_p->writes				\
	: (_t == ERI_ACCESS_PROT_READ ? &_p->prot_reads			\
	: (_t == ERI_ACCESS_PROT_WRITE ? &_p->prot_writes : 0))); })

static uint8_t
race_may_conflict (uint8_t a, uint8_t b)
{
  if (a > b) eri_swap (&a, &b);
  return (a == ERI_ACCESS_READ
	  && (b == ERI_ACCESS_WRITE || b == ERI_ACCESS_PROT_READ))
	 || (a == ERI_ACCESS_WRITE
	     && (b == ERI_ACCESS_WRITE || b == ERI_ACCESS_PROT_WRITE))
	 || (a == ERI_ACCESS_PROT_READ && b == ERI_ACCESS_PROT_READ)
	 || (a == ERI_ACCESS_PROT_WRITE && b == ERI_ACCESS_PROT_WRITE);
}

struct race_confirm_context
{
  eri_file_t log;

  struct race_group *group;
  struct race_unit *unit;

  struct race_cursor cur;
  struct race_block *last;

  uint8_t first;

  uint8_t conflicts[ACCESS_NUM][ACCESS_NUM];
};

static uint8_t
race_collect_conflicts (struct race_confirm_context *ctx)
{
  uint8_t i, j, c = 0;
  for (i = ERI_ACCESS_START; i < ERI_ACCESS_END; ++i)
    for (j = ERI_ACCESS_START; j < ERI_ACCESS_END; ++j)
      {
	eri_log9 (ctx->log, "[RACE] %s %s\n",
		 eri_access_type_str (i), eri_access_type_str (j));
	struct interval_tree *a = race_get_type (i, &ctx->unit->inc);
	struct interval_tree *b = race_get_type (j, &ctx->cur.blk->pushed);

        uint8_t t = 9;
	eri_logn (t, ctx->log, "[RACE] unit: u%lu\n", ctx->unit->id);
	dump_interval_tree (t, ctx->log, a);
	eri_logn (t, ctx->log, "[RACE] block: b%lu\n", ctx->cur.blk->id);
	dump_interval_tree (t, ctx->log, b);

	if ((ctx->conflicts[i - ERI_ACCESS_START][j - ERI_ACCESS_START]
		= race_may_conflict (i, j) && race_ranges_intersects (a, b)))
	  c = 1;
      }

  uint8_t t = 2;
  eri_logn (t, ctx->log, "[RACE] collect unit: u%lu, block b%lu, unit u%lu, ",
	    ctx->unit->id, ctx->cur.blk->id, ctx->cur.unit->id);
  struct race_unit *u;
  for (u = ctx->cur.unit; u->prev; u = u->prev)
    eri_rlogn (t, ctx->log, "u%lu, ", u->id);
  eri_rlogn (t, ctx->log, "conflicted: %u\n", c);

  return c;
}

static uint8_t
race_confirm_prev (struct race_confirm_context *ctx)
{
  uint8_t first = ctx->first;
  ctx->first = 0;

  if (ctx->cur.unit->prev)
    {
      ctx->cur.unit = ctx->cur.unit->prev;
      if (! first || race_collect_conflicts (ctx)) return 1;
    }

  while (ctx->cur.blk != ctx->last)
    {
      ctx->cur.blk = ctx->cur.blk->prev;
      ctx->cur.unit = ctx->cur.blk->unit;

      if (race_collect_conflicts (ctx)) return 1;
    }
  return 0;
}

static void
race_get_conflicts (struct race_confirm_context *ctx, uint8_t type, uint8_t ref_type)
{
  struct race_accesses *acc = race_get_type (type, &ctx->unit->sealed);
  struct race_accesses *ref = race_get_type (ref_type, &ctx->cur.unit->sealed);

  uint64_t id = ctx->unit->id;
  uint64_t ref_id = ctx->cur.unit->id;

  struct race_access *i = race_access_rbt_get_first (acc);
  struct race_access *j = race_access_rbt_get_first (ref);
  while (i && j)
    if (i->addr + i->size <= j->addr) i = race_access_rbt_get_next (i);
    else if (j->addr + j->size <= i->addr) j = race_access_rbt_get_next (j);
    else
      {
        if (i->addr || j->addr)
	  {
	    eri_log_info (ctx->log,
		"conflict detected: rip %lx, %s mem: %lx size: %lu u%lu, "
		"rip %lx, %s, mem: %lx size :%lu u%lu\n",
		i->rip, eri_access_type_str (type), i->addr, i->size, id,
		j->rip, eri_access_type_str (ref_type), j->addr, j->size, ref_id);
	    eri_atomic_store (&ctx->group->error, 1, 0); // TODO
	  }
	i = race_access_rbt_get_next (i);
      }
}

static void
race_confirm_unit (struct race_confirm_context *ctx)
{
  uint8_t i, j;
  for (i = ERI_ACCESS_START; i < ERI_ACCESS_END; ++i)
    for (j = ERI_ACCESS_START; j < ERI_ACCESS_END; ++j)
      if (ctx->conflicts[i - ERI_ACCESS_START][j - ERI_ACCESS_START])
	race_get_conflicts (ctx, i, j);
}

static void
race_do_confirm (eri_file_t log, struct race_group *group,
		 struct race_unit *unit, struct race_ref *ref)
{
  struct race_confirm_context ctx = {
    log, group, unit, { ref->dst->cur, ref->dst->cur->unit }, ref->last, 1
  };

  while (race_confirm_prev (&ctx)) race_confirm_unit (&ctx);
}

static void
race_test_release_cur (struct race *ra)
{
  if (race_ref_lst_get_size (ra) == 0)
    {
      struct eri_mtpool *pool = ra->group->pool;
      race_empty_area (pool, &ra->cur->cur);
      race_release_block (ra->log, pool, ra->cur);
      ra->cur = 0;
    }
}

static void
race_confirm (struct race *ra, struct race_unit *unit)
{
  struct eri_mtpool *pool = ra->group->pool;
  struct race_ref *r, *nr;
  ERI_LST_FOREACH_SAFE (race_ref, ra, r, nr)
    {
      if (r->last == r->dst->cur && r->last->empty_end)
	{
	  race_release_block (ra->log, pool, r->last);
	  race_release (ra->log, r->dst);

	  race_ref_lst_remove (ra, r);
	  race_free_ref (ra->log, pool, r);
	  continue;
	}

      race_do_confirm (ra->log, ra->group, unit, r);
    }
  race_empty_area (ra->group->pool, &unit->inc);
}

static void
race_push_block (struct race *ra, struct race_sync *before)
{
  struct eri_mtpool *pool = ra->group->pool;
  race_seal_unit (ra->log, pool, ra->cur);
  race_empty_area (pool, &ra->cur->cur);
  eri_assert_buf_shrink (&ra->cur->afters);
  ra->cur->before = *before;

  race_add_block (ra);
  race_confirm (ra, ra->cur->prev->unit);
  race_release_block (ra->log, ra->group->pool, ra->cur->prev);
}

static void
race_add_after (struct race *ra, struct race_sync *after)
{
  if (after->type == RACE_SYNC_KEY_VER)
    eri_log2 (ra->log, "[RACE] block: b%lu, unit: u%lu, sync.kv: %lx %lu\n",
	      ra->cur->id, ra->cur->unit->id, after->kv.key, after->kv.ver);

  eri_assert_buf_append (&ra->cur->afters, after, 1);
}

static void
race_lock (struct race *ra)
{
  eri_assert_lock (&ra->group->lock);
}

static void
race_unlock (struct race *ra)
{
  eri_assert_unlock (&ra->group->lock);
}

static struct race *
race_clone (struct race *ra, uint64_t id, eri_file_t log)
{
  eri_log2 (ra->log, "[RACE] call\n");

  struct race *cra = race_create (ra->group, log);
  race_add_block (cra);
  struct race_sync sync = { RACE_SYNC_CLONE, .clone = id };
  race_add_after (cra, &sync);

  if (ra->cur)
    {
      race_lock (ra);
      struct race_ref *r;
      ERI_LST_FOREACH (race_ref, ra, r)
	{
	  if (! r->dst->end)
	    race_add_ref (ra->log, r->dst, cra, cra->cur);
	  race_add_ref (ra->log, cra, r->dst, r->last);
	}
      race_push_block (ra, &sync);
      race_add_ref (ra->log, ra, cra, cra->cur);
      race_add_ref (ra->log, cra, ra, ra->cur);
      race_unlock (ra);
    }
  else
    {
      race_add_block (ra);
      race_add_ref (ra->log, ra, cra, cra->cur);
      race_add_ref (ra->log, cra, ra, ra->cur);
    }

  return cra;
}

static uint8_t
race_unit_is_empty (struct race_unit *unit)
{
  return ! (unit->reads.o || unit->writes.o
	    || unit->prot_reads.o || unit->prot_writes.o);
}

static void
race_push_unit (struct race *ra)
{
  if (race_unit_is_empty (ra->cur->unit)) return;

  struct eri_mtpool *pool = ra->group->pool;
  race_seal_unit (ra->log, pool, ra->cur);

  race_add_unit (ra, ra->cur);
  race_confirm (ra, ra->cur->unit->prev);
}

static void
race_release_blocks (eri_file_t log, struct eri_mtpool *pool,
		     struct race_block *first, struct race_block *last,
		     struct eri_buf *afters)
{
  while (1)
    {
      struct race_block *prev = first->prev;
      if (afters) eri_assert_buf_concat (afters, &first->afters);
      race_release_block (log, pool, first);
      if (first == last) break;
      first = prev;
    }
}

static void
race_end (struct race *ra)
{
  eri_log2 (ra->log, "[RACE] call\n");

  if (! ra->cur) goto out;

  struct eri_mtpool *pool = ra->group->pool;

  race_lock (ra);
  race_push_unit (ra);
  race_empty_area (pool, &ra->cur->cur);
  race_release_block (ra->log, pool, ra->cur);

  ra->end = 1;
  struct race_ref *r, *nr;
  ERI_LST_FOREACH_SAFE (race_ref, ra, r, nr)
    {
      race_release_blocks (ra->log, pool, r->dst->cur, r->last, 0);
      race_release (ra->log, r->dst);
      race_ref_lst_remove (ra, r);
      race_free_ref (ra->log, pool, r);
    }
  ra->cur->empty_end = ! ra->cur->unit->prev;
  race_unlock (ra);

out:
  race_release (ra->log, ra);
}

static void
race_push (struct race *ra)
{
  eri_log2 (ra->log, "[RACE] call\n");

  if (! ra->cur) return;

  race_lock (ra);
  race_push_unit (ra);
  race_test_release_cur (ra);
  race_unlock (ra);
}

static void
race_do_access (struct race *ra, struct eri_access *acc)
{
  uint8_t t = acc->type;

  eri_log9 (ra->log, "[RACE] block: b%lu, addr: %lx, size: %lu, type: %s\n",
	    ra->cur->id, acc->addr, acc->size, eri_access_type_str (t));
  struct race_access a = { acc->addr, acc->size, acc->rip };
  if (! race_ranges_insert (ra->log, ra->group->pool,
			    race_get_type (t, &ra->cur->cur), &a,
			    race_get_type (t, &ra->cur->inc)))
    return;

  struct eri_buf *as = race_get_type (t, ra->cur->unit);
  if (as->o)
    {
      struct race_access *l = (struct race_access *) as->buf + as->o - 1;
      if (l->addr + l->size == a.addr && l->rip == a.rip)
	{
	  l->size += a.size;
	  return;
	}
    }

  a.order = ra->order++;
  eri_assert_buf_append (as, &a, 1);
}

static void
race_access (struct race *ra, struct eri_access *acc, uint64_t n)
{
  if (! ra->cur) return;

  uint64_t i;
  for (i = 0; i < n; ++i) race_do_access (ra, acc + i);
}

static void
race_before (struct race *ra, uint64_t key, uint64_t ver)
{
  eri_log2 (ra->log, "[RACE] call\n");

  if (! ra->cur) return;

  struct race_sync sync = {
    RACE_SYNC_KEY_VER, .kv.key = key, .kv.ver = ver
  };
  race_lock (ra);
  eri_log2 (ra->log, "[RACE] block: b%lu, unit: u%lu, sync.kv: %lx %lu\n",
	    ra->cur->id, ra->cur->unit->id, key, ver);

  race_push_block (ra, &sync);
  race_test_release_cur (ra);
  race_unlock (ra);
}

static uint8_t
race_block_before (struct race_block *blk, struct race_sync *sync)
{
  struct race_sync *before = &blk->before;
  if (before->type != sync->type) return 0;
  return before->type == RACE_SYNC_CLONE ? before->clone == sync->clone
	: before->kv.key == sync->kv.key && before->kv.ver <= sync->kv.ver;
}

static struct race_block *
race_get_last (struct race_block *cur, struct race_block *last,
	       struct race_sync *sync)
{
  while (cur != last && ! race_block_before (cur->prev, sync))
    cur = cur->prev;
  return cur;
}

static void
race_trim_before (struct race *ra, struct race_sync *sync)
{
  struct eri_mtpool *pool = ra->group->pool;

  struct eri_buf afters;
  eri_assert_buf_mtpool_init (&afters, pool, 4, struct race_sync);

  struct race_ref *r, *nr;
  ERI_LST_FOREACH_SAFE (race_ref, ra, r, nr)
    {
      struct race_block *old = r->last;
      struct race_block *last = race_get_last (r->dst->cur, old, sync);
      if (old == last) continue;
      r->last = last;
      race_release_blocks (ra->log, pool, last->prev, old, &afters);
    }

  struct race_sync *a = (void *) afters.buf;
  uint64_t n = afters.o, i;
  for (i = 0; i < n; ++i) race_trim_before (ra, a + i);

  eri_assert_buf_fini (&afters);
}

static void
race_after (struct race *ra, uint64_t key, uint64_t ver)
{
  eri_log2 (ra->log, "[RACE] call\n");

  race_push (ra);
  if (! ra->cur) return;

  struct race_sync sync = {
    RACE_SYNC_KEY_VER, .kv.key = key, .kv.ver = ver
  };
  race_add_after (ra, &sync);

  race_lock (ra);
  race_trim_before (ra, &sync);
  race_unlock (ra);

  eri_log2 (ra->log, "[RACE]\n");
}

struct trans_key
{
  uint64_t rip;
  uint8_t tf;
};

struct trans
{
  struct trans_key key;

  uint64_t ref_count;

  struct eri_trans *trans;
  uint64_t len;
  uint64_t wait;
  uint32_t done;

  ERI_RBT_NODE_FIELDS (trans, struct trans)
};

struct eri_analyzer_group
{
  struct eri_mtpool *pool;
  struct eri_range *map_range;

  const char *log;

  uint64_t page_size;
  uint64_t file_buf_size;
  uint32_t max_inst_count;
  uint64_t max_race_enter;

  int32_t pid;

  void *error;

  eri_lock_t trans_lock;
  ERI_RBT_TREE_FIELDS (trans, struct trans)

  eri_lock_t mm_prot_lock;
  struct interval_tree read_perms;
  struct interval_tree write_perms;

  struct race_group race;
};

static uint8_t
trans_key_less_than (struct eri_analyzer_group *g,
		     struct trans_key *a, struct trans_key *b)
{
  return a->rip == b->rip ? a->tf < b->tf : a->rip < b->rip;
}

ERI_DEFINE_RBTREE (static, trans, struct eri_analyzer_group,
		   struct trans, struct trans_key, trans_key_less_than)

struct eri_analyzer
{
  struct eri_analyzer_group *group;
  struct eri_buf_file log;

  struct eri_entry *entry;
  int32_t tid;

  void *args;

  struct eri_siginfo *sig_info;

  struct eri_trans_active *act;
  struct eri_siginfo act_sig_info;
  struct eri_mcontext act_sig_mctx;

  uint64_t race_enter;
  struct race *race;
};

struct eri_analyzer_group *
eri_analyzer_group__create (struct eri_analyzer_group__create_args *args)
{
  eri_trans_init_translate ();

  struct eri_analyzer_group *group
			= eri_assert_mtmalloc (args->pool, sizeof *group);
  group->pool = args->pool;
  group->map_range = args->map_range;
  group->log = args->log;
  group->page_size = args->page_size;
  group->file_buf_size = args->file_buf_size;
  group->max_inst_count = args->max_inst_count;
  group->max_race_enter = args->max_race_enter;
  group->pid = args->pid;
  group->error = args->error;

  group->trans_lock = 0;
  ERI_RBT_INIT_TREE (trans, group);

  group->mm_prot_lock = 0;
  ERI_RBT_INIT_TREE (interval, &group->read_perms);
  ERI_RBT_INIT_TREE (interval, &group->write_perms);

  race_init_group (&group->race, group->pool);
  return group;
}

static void
destroy_trans (struct eri_mtpool *pool, struct trans *t)
{
  if (t->trans) eri_trans_destroy (pool, t->trans);
  eri_assert_mtfree (pool, t);
}

void
eri_analyzer_group__destroy (struct eri_analyzer_group *group)
{
  struct trans *t, *nt;
  ERI_RBT_FOREACH_SAFE (trans, group, t, nt)
    {
      trans_rbt_remove (group, t);
      eri_xassert (t->ref_count == 0, eri_info);
      destroy_trans (group->pool, t);
    }
  empty_interval_tree (group->pool, &group->read_perms);
  empty_interval_tree (group->pool, &group->write_perms);
  eri_assert_mtfree (group->pool, group);
}

struct eri_analyzer *
eri_analyzer__create (struct eri_analyzer__create_args *args)
{
  struct eri_analyzer_group *group = args->group;
  struct eri_analyzer *al = eri_assert_mtmalloc (group->pool, sizeof *al);
  al->group = group;
  eri_open_log (group->pool, &al->log, group->log, "a", args->id,
		eri_enabled_debug () ? 0 : group->file_buf_size);
  al->entry = args->entry;
  al->args = args->args;
  al->sig_info = 0;
  al->act = 0;
  al->act_sig_info.sig = 0;

  al->race_enter = 0;
  struct eri_analyzer *pal = args->parent;
  eri_file_t log = al->log.file;
  al->race = pal ? race_clone (pal->race, args->id, log)
		 : race_create (&group->race, log);
  return al;
}

void
eri_analyzer__set_tid (struct eri_analyzer *al, int32_t tid)
{
  al->tid = tid;
}

void
eri_analyzer__destroy (struct eri_analyzer *al)
{
  race_end (al->race);

  struct eri_mtpool *pool = al->group->pool;
  eri_close_log (pool, &al->log);
  eri_assert_mtfree (al->group->pool, al);
}

static eri_noreturn void
error (struct eri_analyzer *al)
{
  eri_noreturn void (*e) (void *) = al->group->error;
  e (al->args);
}

static uint8_t
exec_copy_user (void *dst, const void *src, uint64_t size,
	        struct eri_siginfo *info, void *args)
{
  /* XXX: PROT_EXEC */
  struct eri_analyzer *al = args;
  eri_atomic_store (&al->sig_info, info, 1);
  if (! eri_entry__copy_from_user (al->entry, dst, src, size, 0))
    return 0;
  eri_atomic_store (&al->sig_info, 0, 1);
  return 1;
}

static eri_noreturn void analysis (struct eri_trans_active *act);

static eri_noreturn void
analysis_enter (struct eri_analyzer *al,
	        struct eri_registers *regs)
{
  if (eri_global_enable_debug >= 2)
    eri_log (al->log.file, "rip %lx, rax %lx, rbx %lx, rcx %lx, rdx %lx, "
	"rsi %lx, rdi %lx, rbp %lx, rsp %lx, r8 %lx, r9 %lx, r10 %lx, "
	"r11 %lx, r12 %lx r13 %lx, r14 %lx, r15 %lx, rflags %lx\n",
	regs->rip, regs->rax, regs->rbx, regs->rcx, regs->rdx, regs->rsi,
	regs->rdi, regs->rbp, regs->rsp, regs->r8, regs->r9, regs->r10,
	regs->r11, regs->r12, regs->r13,  regs->r14, regs->r15,
	regs->rflags);
  else
    eri_log (al->log.file, "rip = %lx rsp = %lx rsi = %lx rdi = %lx\n",
	     regs->rip, regs->rsp, regs->rsi, regs->rdi);

  eri_assert (! eri_within (al->group->map_range, regs->rip));

  struct eri_analyzer_group *group = al->group;

  if (eri_atomic_load (&group->race.error, 0)) error (al);

  al->race_enter = (al->race_enter + 1) % group->max_race_enter;
  if (! al->race_enter) race_push (al->race);

  eri_assert_lock (&group->trans_lock);
  struct trans_key key = { regs->rip, !! (regs->rflags & ERI_RFLAGS_TF) };
  struct trans *trans = trans_rbt_get (group, &key, ERI_RBT_EQ);
  if (! trans)
    {
      trans = eri_assert_mtmalloc (group->pool, sizeof *trans);
      trans->key = key;
      trans->ref_count = 1;
      trans->wait = 0;
      trans->done = 0;
      trans_rbt_insert (group, trans);
      eri_assert_unlock (&group->trans_lock);

      struct eri_translate_args args = {
	group->pool, al->log.file, group->map_range, group->page_size,
	group->max_inst_count, key.rip, key.tf, trans, exec_copy_user,
	al, analysis, &trans->len
      };

      trans->trans = eri_translate (&args);
      eri_atomic_store (&trans->done, 1, 0);

      if (eri_atomic_load (&trans->wait, 1))
        eri_assert_syscall (futex, &trans->done,
			    ERI_FUTEX_WAKE, ERI_INT_MAX);
    }
  else
    {
      eri_atomic_inc (&trans->ref_count, 0);
      eri_assert_unlock (&group->trans_lock);
      if (! eri_atomic_load (&trans->done, 0))
	{
	  eri_atomic_inc (&trans->wait, 1);
	  eri_assert_sys_futex_wait (&trans->done, 0, 0);
	  eri_atomic_dec (&trans->wait, 1);
	}
    }

  struct eri_trans *tr = trans->trans;
  if (! tr)
    {
      eri_atomic_dec (&trans->ref_count, 1);
      error (al);
    }

  struct eri_trans_create_active_args args = {
    group->pool, al, tr, eri_entry__get_stack (al->entry) - 8, regs
  };

  struct eri_trans_active *act = eri_trans_create_active (&args);
  eri_atomic_store (&al->act, act, 0);

  eri_log3 (al->log.file, "leave\n");
  eri_trans_enter_active (act);
}

static void
raise (struct eri_analyzer *al,
       struct eri_siginfo *info, struct eri_registers *regs)
{
  al->act_sig_info = *info;
  eri_mcontext_from_registers (&al->act_sig_mctx, regs);
  al->act_sig_mctx.rflags |= 0x202; /* IF & 0x2 */
  eri_assert_syscall (tgkill, al->group->pid, al->tid, ERI_SIGRTMIN + 1);
}

static void
raise_single_step (struct eri_analyzer *al, struct eri_registers *regs)
{
  struct eri_siginfo info = { .sig = ERI_SIGTRAP, .code = ERI_TRAP_TRACE };
  eri_log9 (al->log.file, "%lx %lx\n", regs->rsi, regs->rflags);
  raise (al, &info, regs);
}

eri_noreturn void
eri_analyzer__enter (struct eri_analyzer *al, struct eri_registers *regs)
{
  if (regs->rflags & ERI_RFLAGS_TF) raise_single_step (al, regs);
  analysis_enter (al, regs);
}

static void
release_active (struct eri_analyzer *al)
{
  struct eri_trans_active *act = al->act;
  eri_atomic_store (&al->act, 0, 0);
  struct trans *trans = eri_trans_active_get_trans_data (act);
  eri_atomic_dec (&trans->ref_count, 1);
  eri_trans_destroy_active (al->group->pool, act);
}

static void
dump_accesses (eri_file_t log, uint8_t t, struct eri_access *a, uint64_t n)
{
  uint64_t i;
  for (i = 0; i < n; ++i)
    eri_rlogn (t, log, "  %lx %lu %s\n",
	       a[i].addr, a[i].size, eri_access_type_str (a[i].type));
}

static void
check_trans_cache (eri_file_t log,
		   struct eri_analyzer_group *group, struct eri_access *acc)
{
  if (acc->type != ERI_ACCESS_WRITE && acc->type != ERI_ACCESS_PROT_READ)
    return;

  struct eri_range range = { acc->addr, acc->addr + acc->size };

  eri_assert_lock (&group->trans_lock);
  struct trans *t, *nt;
  ERI_RBT_FOREACH_SAFE (trans, group, t, nt)
    if (! eri_atomic_load (&t->ref_count, 0)
	&& t->trans /* don't bother to remove error */
	&& eri_across (&range, t->key.rip, t->len))
      {
	eri_log (log, "remove trans cache %lx %lu\n", t->key.rip, t->len);
	trans_rbt_remove (group, t);
	destroy_trans (group->pool, t);
      }
  eri_assert_unlock (&group->trans_lock);
}

static void
update_access (struct eri_analyzer *al, struct eri_access *acc, uint64_t n,
	       const char *msg)
{
  if (! n) return;

  uint8_t t = 3;
  eri_logn (t, al->log.file, "%s %lu\n", msg, n);
  dump_accesses (al->log.file, t, acc, n);

  uint64_t i;
  for (i = 0; i < n; ++i)
    check_trans_cache (al->log.file, al->group, acc + i);

  race_access (al->race, acc, n);
}

static void
update_access_from_buf (struct eri_analyzer *al, struct eri_buf *acc,
			const char *msg)
{
  update_access (al, (void *) acc->buf, acc->o, msg);
}

static eri_noreturn void
analysis (struct eri_trans_active *act)
{
  struct eri_analyzer *al = eri_trans_active_get_data (act);
  eri_file_t log = al->log.file;

  struct eri_registers regs;
  struct eri_siginfo info;
  struct eri_buf accesses;
  eri_assert_buf_mtpool_init (&accesses, al->group->pool, 16,
			      struct eri_access);
  struct eri_trans_leave_active_args args = { act, log, &regs, &accesses };
  uint8_t tf = eri_trans_leave_active (&args, &info);
  release_active (al);

  update_access_from_buf (al, &accesses, "accesses");
  eri_assert_buf_fini (&accesses);

  if (info.sig) raise (al, &info, &regs);
  else if (tf) raise_single_step (al, &regs);

  struct eri_entry *en = al->entry;
  if (eri_within (al->group->map_range, regs.rip))
    {
      struct eri_registers *en_regs = eri_entry__get_regs (en);
      regs.rbx = en_regs->rbx;
      regs.rip = en_regs->rip;
      *en_regs = regs;
      eri_noreturn void (*entry) (void *) = eri_entry__get_entry (en);
      entry (en);
    }
  else analysis_enter (al, &regs);
}

void
eri_analyzer__sig_handler (struct eri_analyzer__sig_handler_args *args)
{
  struct eri_analyzer *al = args->analyzer;
  struct eri_siginfo *info = args->info;
  struct eri_mcontext *mctx = &args->ctx->mctx;

  eri_file_t log = al->log.file;

  if (eri_entry__sig_is_access_fault (al->entry, info))
    {
      if (al->sig_info)
	{
	  *al->sig_info = *info;
	  al->sig_info = 0;

	  eri_entry__sig_access_fault (al->entry, mctx, info->fault.addr);
	  return;
	}

      eri_lassert (log, ! al->act && ! al->act_sig_info.sig);
    }

  if (info->code == ERI_SI_TKILL && info->kill.pid == al->group->pid
      && al->act_sig_info.sig)
    {
      struct eri_mcontext saved = *mctx;
      *info = al->act_sig_info;
#define GET_MCTX(creg, reg) mctx->reg = al->act_sig_mctx.reg;
      ERI_FOREACH_REG (GET_MCTX)
      al->act_sig_info.sig = 0;

      if (args->handler (info, args->ctx, args->args)) return;

      *mctx = saved;
      return;
    }

  if (! al->act
      || ! eri_trans_sig_within_active (al->act, mctx->rip))
    {
      args->handler (info, args->ctx, args->args);
      return;
    }

  struct eri_registers regs;
  struct eri_buf accesses;
  eri_assert_buf_mtpool_init (&accesses, al->group->pool, 16,
			      struct eri_access);
  struct eri_trans_leave_active_args leave_args
			= { al->act, log, &regs, &accesses };
  eri_trans_sig_leave_active (&leave_args, info, mctx);

  struct eri_mcontext saved = *mctx;
  eri_mcontext_from_registers (mctx, &regs);

  if (args->handler (info, args->ctx, args->args)) release_active (al);
  else *mctx = saved;

  update_access_from_buf (al, &accesses, "sig leave accesses");
  eri_assert_buf_fini (&accesses);
}

struct update_mm_prot_diff_args
{
  eri_file_t log;
  struct eri_buf *accesses;
  uint64_t rip;
  uint8_t type;
};

static void
update_mm_prot_diff (uint64_t start, uint64_t end, void *args)
{
  struct update_mm_prot_diff_args *a = args;
  eri_append_access (a->accesses, start, end - start, a->rip, a->type);
}

static void
update_mm_prot (struct eri_analyzer *al, uint8_t read,
		struct eri_range *range, uint8_t permitted)
{
  struct eri_analyzer_group *group = al->group;
  struct eri_mtpool *pool = group->pool;

  struct eri_buf accesses;
  eri_assert_buf_mtpool_init (&accesses, pool, 16, struct eri_access);

  struct update_mm_prot_diff_args args = {
    al->log.file, &accesses, eri_entry__get_start (al->entry),
    read ? ERI_ACCESS_PROT_READ : ERI_ACCESS_PROT_WRITE
  };

  update_interval_tree (pool,
		read ? &group->read_perms : &group->write_perms,
		range->start, range->end, permitted,
		update_mm_prot_diff, &args);

  update_access_from_buf (al, &accesses,
		 permitted ? "mm permitted" : "mm not permitted");
  eri_assert_buf_fini (&accesses);
}

void
eri_analyzer__update_mm_prot (struct eri_analyzer *al,
			      struct eri_range range, int32_t prot)
{
  struct eri_analyzer_group *group = al->group;

  /* XXX: already protected by the caller now */
  eri_assert_lock (&group->mm_prot_lock);
  update_mm_prot (al, 1, &range, !! (prot & ERI_PROT_READ));
  update_mm_prot (al, 0, &range, !! (prot & ERI_PROT_WRITE));
  eri_assert_unlock (&group->mm_prot_lock);
}

void
eri_analyzer__update_access (struct eri_analyzer *al,
			     struct eri_access *acc)
{
  update_access (al, acc, 1, "extern");
}

void
eri_analyzer__race_before (struct eri_analyzer *al,
			   uint64_t key, uint64_t ver)
{
  race_before (al->race, key, ver);
  al->race_enter = 0;
}

void
eri_analyzer__race_after (struct eri_analyzer *al,
			  uint64_t key, uint64_t ver)
{
  race_after (al->race, key, ver);
}
