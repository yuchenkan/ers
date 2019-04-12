#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/lock.h>
#include <lib/rbtree.h>
#include <lib/malloc.h>

#include <common/thread.h>

#include <analysis/analyzer.h>

struct entry
{
  uint64_t rip;
  uint64_t ref_count;

  uint64_t wait;
  void *translated;
};

struct eri_analyzer_group
{
  struct eri_mtpool *pool;

  struct eri_lock entry_lock;
  ERI_RBT_TREE_FIELDS (entry, struct entry)
};

ERI_DEFINE_RBTREE (static, entry, struct eri_analyzer_group,
		   struct entry, uint64_t, eri_less_than)

struct eri_analyzer
{
  struct eri_analyzer_group *group;
};

struct eri_analyzer_group *
eri_analyzer_group__create (struct eri_analyzer_group__create_args *args)
{
  return 0;
}

void
eri_analyzer_group__destroy (struct eri_analyzer_group *group)
{
}

struct eri_analyzer *
eri_analyzer__create (struct eri_analyzer__create_args *args)
{
  return 0;
}

void
eri_analyzer__destroy (struct eri_analyzer *analyzer)
{
}

eri_noreturn void
eri_analyzer__enter (struct eri_analyzer *analyzer,
		     struct eri_registers *regs)
{
  struct eri_analyzer_group *group = analyzer->group;
  eri_lock (group->entry_lock);
  struct entry *entry = entry_rbt_get (group, &regs->rip, ERI_RBT_EQ);
  if (! entry)
    {
      entry = eri_mtmalloc (group->pool, sizeof *entry);
      entry->rip = regs->rip;
      entry->ref_count = 1;
      entry->wait = 0;
      entry->translated = 1; /* for no 64 bit futex */
      entry_rbt_insert (group, entry);
      eri_unlock (group->entry_lock);
    }
  else
    {
      ++entry->ref_count;
      eri_unlock (group->entry_lock);
      if (eri_atomic_load (&entry->translated, 0) == 1)
	{
	  eri_atomic_inc (&entry->wait, 1);
	  eri_atomic_dec (&entry->wait, 1);
	}
    }

  eri_assert_unreachable ();
}
