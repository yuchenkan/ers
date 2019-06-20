#include <lib/compiler.h>
#include <lib/cpu.h>
#include <lib/util.h>
#include <lib/lock.h>
#include <lib/atomic.h>
#include <lib/buf.h>
#include <lib/rbtree.h>
#include <lib/malloc.h>

#include <common/debug.h>
#include <common/common.h>
#include <common/entry.h>

#include <analysis/analyzer.h>
#include <analysis/translate.h>

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
  uint64_t wait;
  uint32_t done;

  ERI_RBT_NODE_FIELDS (trans, struct trans)
};

struct mm_perm
{
  uint64_t start;
  uint64_t end;
  ERI_RBT_NODE_FIELDS (mm_perm, struct mm_perm)
};

struct mm_perms
{
  ERI_RBT_TREE_FIELDS (mm_perm, struct mm_perm)
};

ERI_DEFINE_RBTREE (static, mm_perm, struct mm_perms, struct mm_perm,
		   uint64_t, eri_less_than)

struct eri_analyzer_group
{
  struct eri_mtpool *pool;
  struct eri_range *map_range;

  const char *log;

  uint64_t page_size;
  uint64_t file_buf_size;
  uint32_t max_inst_count;

  int32_t *pid;

  uint8_t exit;

  struct eri_lock trans_lock;
  ERI_RBT_TREE_FIELDS (trans, struct trans)

  struct eri_lock mm_prot_lock;
  struct mm_perms read_perms;
  struct mm_perms write_perms;
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
  int32_t *tid;

  struct eri_siginfo *sig_info;

  struct eri_trans_active *act;
  struct eri_siginfo act_sig_info;
  struct eri_mcontext act_sig_mctx;

  void *exit;
  void *args;
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
  group->pid = args->pid;
  group->exit = 0;

  eri_init_lock (&group->trans_lock, 0);
  ERI_RBT_INIT_TREE (trans, group);
  return group;
}

static void
free_mm_perms (struct eri_mtpool *pool, struct mm_perms *perms)
{
  struct mm_perm *p, *np;
  ERI_RBT_FOREACH_SAFE (mm_perm, perms, p, np)
    {
      mm_perm_rbt_remove (perms, p);
      eri_assert_mtfree (pool, p);
    }
}

void
eri_analyzer_group__destroy (struct eri_analyzer_group *group)
{
  struct trans *t, *nt;
  ERI_RBT_FOREACH_SAFE (trans, group, t, nt)
    {
      trans_rbt_remove (group, t);
      eri_xassert (t->ref_count == 0, eri_info);
      if (t->trans) eri_trans_destroy (group->pool, t->trans);
      eri_assert_mtfree (group->pool, t);
    }
  free_mm_perms (group->pool, &group->read_perms);
  free_mm_perms (group->pool, &group->write_perms);
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
  al->tid = args->tid;
  al->exit = args->exit;
  al->args = args->args;
  al->sig_info = 0;
  al->act = 0;
  al->act_sig_info.sig = 0;
  return al;
}

void
eri_analyzer__destroy (struct eri_analyzer *al)
{
  struct eri_mtpool *pool = al->group->pool;
  eri_close_log (pool, &al->log);
  eri_assert_mtfree (al->group->pool, al);
}

static eri_noreturn void
exit (struct eri_analyzer *al)
{
  eri_noreturn void (*e) (void *) = al->exit;
  e (al->args);
}

eri_noreturn void
eri_analyzer__exit_group (struct eri_analyzer *al)
{
  // TODO do analysis
  eri_atomic_store (&al->group->exit, 1, 0);
  exit (al);
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
  eri_log2 (al->log.file, "rip = %lx rcx = %lx r11 = %lx rflags = %lx\n",
	    regs->rip, regs->rcx, regs->r11, regs->rflags);
  eri_assert (! eri_within (al->group->map_range, regs->rip));

  if (eri_atomic_load (&al->group->exit, 0)) exit (al);

  struct eri_analyzer_group *group = al->group;
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
	al, analysis
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
      eri_analyzer__exit_group (al);
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
  eri_assert_syscall (tgkill, *al->group->pid, *al->tid, ERI_SIGRTMIN + 1);
}

static void
raise_single_step (struct eri_analyzer *al, struct eri_registers *regs)
{
  struct eri_siginfo info = { .sig = ERI_SIGTRAP, .code = ERI_TRAP_TRACE };
  eri_log (al->log.file, "%lx %lx\n", regs->rsi, regs->rflags);
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
update_access (struct eri_analyzer *al, struct eri_access *acc, uint64_t n,
	       const char *msg)
{
  if (! n) return;

  uint8_t t = 3;
  eri_logn (t, al->log.file, "%s\n", msg);
  dump_accesses (al->log.file, t, acc, n);

  // TODO
}

static void
update_access_from_buf (struct eri_analyzer *al, struct eri_buf *acc,
			const char *msg)
{
  update_access (al, (void *) acc->buf,
		 acc->off / sizeof (struct eri_access), msg);
}

static eri_noreturn void
analysis (struct eri_trans_active *act)
{
  struct eri_analyzer *al = eri_trans_active_get_data (act);
  eri_file_t log = al->log.file;

  struct eri_registers regs;
  struct eri_siginfo info;
  struct eri_buf accesses;
  eri_assert_buf_mtpool_init (&accesses, al->group->pool, 16);
  struct eri_trans_leave_active_args args = { act, log, &regs, &accesses };
  uint8_t tf = eri_trans_leave_active (&args, &info);
  release_active (al);

  update_access_from_buf (al, &accesses, "accesses");
  eri_assert_buf_fini (&accesses);

  // TODO do analysis

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

  if (info->code == ERI_SI_TKILL && info->kill.pid == *al->group->pid
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
  eri_assert_buf_mtpool_init (&accesses, al->group->pool, 16);
  struct eri_trans_leave_active_args leave_args
			= { al->act, log, &regs, &accesses };
  eri_trans_sig_leave_active (&leave_args, info, mctx);

  struct eri_mcontext saved = *mctx;
  eri_mcontext_from_registers (mctx, &regs);

  if (args->handler (info, args->ctx, args->args)) release_active (al);
  else *mctx = saved;

  update_access_from_buf (al, &accesses, "sig leave accesses");
  eri_assert_buf_fini (&accesses);

  // TODO do analysis
}

static void
update_mm_prot (struct eri_analyzer *al, uint8_t read,
		struct eri_range *range, uint8_t permitted)
{
  struct eri_analyzer_group *group = al->group;
  struct mm_perms *perms = read ? &group->read_perms : &group->write_perms;

  if (permitted)
    {
      struct mm_perm *eq = mm_perm_rbt_get (perms, &range->start, ERI_RBT_EQ);
      if (eq && eq->end == range->end) return;
    }

  struct eri_mtpool *pool = group->pool;
  uint8_t type = read ? ERI_ACCESS_PROT_READ : ERI_ACCESS_PROT_WRITE;

  struct eri_buf accesses;
  eri_assert_buf_mtpool_init (&accesses, pool, 16);

  struct mm_perm *lt = mm_perm_rbt_get (perms, &range->start, ERI_RBT_LT);

  uint64_t start = range->start, end = range->end;
  uint64_t perm_start = range->start;
  if (lt && lt->end > start)
    {
      if (permitted)
	{
	  mm_perm_rbt_remove (perms, lt);
	  start = lt->start;
	  perm_start = lt->end;
	  eri_assert_mtfree (pool, lt);
	}
      else
	{
	  eri_append_access (&accesses, start, lt->end - start, type);
	  lt->end = start;
	}
    }

  struct mm_perm *it = lt ? mm_perm_rbt_get_next (lt)
			  : mm_perm_rbt_get_first (perms);

  while (it && it->end <= end)
    {
      uint64_t acc_start = permitted ? perm_start : it->start;
      eri_append_access (&accesses, acc_start,
		(permitted ? it->start : it->end) - acc_start, type);

      struct mm_perm *tmp = mm_perm_rbt_get_next (it);
      mm_perm_rbt_remove (perms, it);
      eri_assert_mtfree (pool, it);
      it = tmp;
    }

  if (it && it->start < end)
    {
      mm_perm_rbt_remove (perms, it);
      if (permitted)
	{
	  eri_append_access (&accesses, perm_start,
			     it->start - perm_start, type);
	  end = it->end;
	  eri_assert_mtfree (pool, it);
	}
      else
	{
	  eri_append_access (&accesses, it->start, end - it->start, type);
	  it->start = end;
	  mm_perm_rbt_insert (perms, it);
	}
    }
  else if (permitted)
    eri_append_access (&accesses, perm_start, end - perm_start, type);

  if (permitted)
    {
      it = eri_assert_mtmalloc (pool, sizeof *it);
      it->start = start;
      it->end = end;
      mm_perm_rbt_insert (perms, it);
    }

  // TODO do analysis
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
eri_analyzer__update_access (struct eri_analyzer *al, struct eri_access *acc)
{
  update_access (al, acc, 1, "extern");
}
