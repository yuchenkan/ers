#include <lib/util.h>
#include <lib/malloc.h>
#include <lib/rbtree.h>
#include <lib/list.h>
#include <lib/lock.h>
#include <lib/syscall.h>

#include <common/debug.h>
#include <common/common.h>
#include <common/serial.h>
#include <common/entry.h>

#include <live/common.h>
#include <live/thread-futex.h>
#include <live/signal-thread.h>

struct waiter
{
  int32_t lock;
  int32_t mask;

  ERI_LST_NODE_FIELDS (waiter)
};

struct futex
{
  uint64_t user_addr;

  /* TODO: priority */
  ERI_LST_LIST_FIELDS (waiter)

  ERI_RBT_NODE_FIELDS (futex, struct futex)
};

ERI_DEFINE_LIST (static, waiter, struct futex, struct waiter)

struct slot
{
  eri_lock_t lock;

  ERI_RBT_TREE_FIELDS (futex, struct futex)
};

ERI_DEFINE_RBTREE (static, futex, struct slot,
		   struct futex, uint64_t, eri_less_than)

struct eri_live_thread_futex_group
{
  struct eri_mtpool *pool;

  struct slot *table;
  uint64_t table_size;

  struct eri_live_atomic *atomic;
};

struct eri_live_thread_futex
{
  struct eri_live_thread_futex_group *group;
  struct eri_entry *entry;
  eri_file_t log;
};

struct eri_live_thread_futex_group *
eri_live_thread_futex__create_group (struct eri_mtpool *pool,
		uint64_t table_size, struct eri_live_atomic *atomic)
{
  struct eri_live_thread_futex_group *group = eri_assert_mtmalloc_struct (
	pool, typeof (*group), (table, table_size * sizeof *group->table));
  group->pool = pool;
  eri_memset (group->table, 0, table_size * sizeof *group->table);
  group->table_size = table_size;
  group->atomic = atomic;
  return group;
}

void
eri_live_thread_futex__destroy_group (
				struct eri_live_thread_futex_group *group)
{
  eri_assert_mtfree (group->pool, group);
}

struct eri_live_thread_futex *
eri_live_thread_futex__create (struct eri_live_thread_futex_group *group,
			       struct eri_entry *entry, eri_file_t log)
{
  struct eri_live_thread_futex *th_ftx = eri_assert_mtmalloc (group->pool,
							sizeof *th_ftx);
  th_ftx->group = group;
  th_ftx->entry = entry;
  th_ftx->log = log;
  eri_log (log, "create thread futex %lx\n", th_ftx);
  return th_ftx;
}

void
eri_live_thread_futex__destroy (struct eri_live_thread_futex *th_ftx)
{
  eri_assert_mtfree (th_ftx->group->pool, th_ftx);
}

static struct slot *
get_slot (struct eri_live_thread_futex_group *group, uint64_t user_addr)
{
  return group->table + eri_hash (user_addr) % group->table_size;
}

static struct slot *
lock_slot (struct eri_live_thread_futex_group *group, uint64_t user_addr)
{
  struct slot *slot = get_slot (group, user_addr);
  eri_assert_lock (&slot->lock);
  return slot;
}

static void
lock_slot2 (struct eri_live_thread_futex_group *group,
	    uint64_t *user_addr, struct slot **slot)
{
  slot[0] = get_slot (group, user_addr[0]);
  slot[1] = get_slot (group, user_addr[1]);
  if (slot[0] == slot[1]) eri_assert_lock (&slot[0]->lock);
  else if (slot[0] < slot[1])
    {
      eri_assert_lock (&slot[0]->lock);
      eri_assert_lock (&slot[1]->lock);
    }
  else
    {
      eri_assert_lock (&slot[1]->lock);
      eri_assert_lock (&slot[0]->lock);
    }
}

static void
unlock_slot2 (struct slot **slot)
{
  eri_assert_unlock (&slot[0]->lock);
  if (slot[0] != slot[1])
    eri_assert_unlock (&slot[1]->lock);
}

static uint8_t
may_remove_free (eri_file_t log, struct eri_mtpool *pool,
		 struct slot *slot, struct futex *futex)
{
  if (waiter_lst_get_size (futex)) return 0;
  eri_log (log, "remove %lx\n", futex);
  futex_rbt_remove (slot, futex);
  eri_assert_mtfree (pool, futex);
  return 1;
}

static uint8_t
remove_waiter (eri_file_t log, struct eri_mtpool *pool, struct slot *slot,
	       struct futex *futex, struct waiter *waiter)
{
  waiter_lst_remove (futex, waiter);
  return may_remove_free (log, pool, slot, futex);
}

static uint64_t
wake (eri_file_t log, struct futex *futex,
      int32_t max, uint32_t mask)
{
  int32_t i = max;
  struct waiter *w, *nw;
  ERI_LST_FOREACH_SAFE (waiter, futex, w, nw)
    {
      /* XXX: seems kernel may wake up at least one waiter */
      if (i <= 0) break;

      eri_log (log, "wake mask, waiter mask %x %x, waiter %lx\n", mask, w->mask, w);
      if ((mask & w->mask) == 0) continue;

      waiter_lst_remove (futex, w);
      w->lock = 0;
      eri_lassert_syscall (log, futex, &w->lock,
			   ERI_FUTEX_WAKE_PRIVATE, 1);
      --i;
    }
  return max - i;
}

static uint64_t
wake_free (struct eri_live_thread_futex *th_ftx, struct slot *slot,
	   struct futex *futex, int32_t max, uint32_t mask)
{
  if (! futex) return 0;

  uint64_t res = wake (th_ftx->log, futex, max, mask);
  may_remove_free (th_ftx->log, th_ftx->group->pool, slot, futex);
  return res;
}

static struct futex *
create (struct eri_mtpool *pool, struct slot *slot, uint64_t user_addr)
{
  struct futex *futex = eri_assert_mtmalloc (pool, sizeof *futex);
  futex->user_addr = user_addr;
  ERI_LST_INIT_LIST (waiter, futex);
  futex_rbt_insert (slot, futex);
  return futex;
}

static int32_t
load_user (struct eri_live_thread_futex *th_ftx, uint64_t user_addr,
	   struct eri_atomic_record *rec)
{
  int32_t cur;
  struct eri_live_atomic_args args = {
    th_ftx->log, th_ftx->entry, ERI_OP_ATOMIC_LOAD, (void *) user_addr,
    sizeof (int32_t), rec, &cur
  };
  eri_live_atomic (th_ftx->group->atomic, &args);
  return cur;
}

static uint64_t
load_test_user (struct eri_live_thread_futex *th_ftx, uint64_t user_addr,
		struct eri_atomic_record *rec, int32_t cmp_arg)
{
  int32_t cur = load_user (th_ftx, user_addr, rec);
  if (! rec->ok) return ERI_EFAULT;

  return cur != cmp_arg ? ERI_EAGAIN :  0;
}

void
eri_live_thread_futex__wait (struct eri_live_thread_futex *th_ftx,
			     struct eri_live_thread_futex__wait_args *args)
{
  struct eri_live_thread_futex_group *group = th_ftx->group;

  uint64_t user_addr = args->user_addr;
  struct eri_syscall_futex_record *rec = args->rec;

  struct slot *slot = lock_slot (group, user_addr);

  uint64_t res;
  struct futex *futex = futex_rbt_get (slot, &user_addr, ERI_RBT_EQ);

  if ((res = load_test_user (th_ftx, user_addr, &rec->atomic, args->cmp_arg)))
    goto unlock_out;

   if (! futex) futex = create (group->pool, slot, user_addr);

  struct waiter waiter = { 1, args->mask };
  waiter_lst_append (futex, &waiter);
  eri_assert_unlock (&slot->lock);

  struct eri_timespec *timeout = args->timeout;
  if (timeout && ! args->abs_time)
    {
      struct eri_timespec time;
      eri_lassert_syscall (th_ftx->log, clock_gettime,
	args->clock_real_time ? ERI_CLOCK_REALTIME : ERI_CLOCK_MONOTONIC,
	&time);

      eri_timespec_add (timeout, &time);
    }

  struct eri_sys_syscall_args sys_args = {
    __NR_futex,
    { (uint64_t) &waiter.lock,
      ERI_FUTEX_WAIT_BITSET_PRIVATE
	| (args->clock_real_time ? ERI_FUTEX_CLOCK_REALTIME : 0), 1,
      (uint64_t) timeout, 0, -1 }
  };
  do
    res = eri_entry__sys_syscall_interruptible (th_ftx->entry, &sys_args)
		? sys_args.result : ERI_ERESTART;
  while (res == 0 && eri_atomic_load (&waiter.lock, 1));

  if (res == ERI_EAGAIN) res = 0;
  else if (eri_syscall_is_error (res))
    {
      eri_lassert (th_ftx->log,
		   timeout ? res == ERI_EINTR || res == ERI_ETIMEDOUT
			   : res == ERI_ERESTART);

      eri_assert_lock (&slot->lock);
      if (! waiter.lock) res = 0;
      else remove_waiter (th_ftx->log, group->pool, slot, futex, &waiter);
      eri_assert_unlock (&slot->lock);
    }
  rec->res.result = res;
  return;

unlock_out:
  eri_assert_unlock (&slot->lock);
  rec->res.result = res;
}

uint64_t
eri_live_thread_futex__wake (struct eri_live_thread_futex *th_ftx,
			     uint64_t user_addr, int32_t max, uint32_t mask)
{
  struct eri_live_thread_futex_group *group = th_ftx->group;

  struct slot *slot = lock_slot (group, user_addr);
  struct futex *futex = futex_rbt_get (slot, &user_addr, ERI_RBT_EQ);
  uint64_t res = wake_free (th_ftx, slot, futex, max, mask);
  eri_assert_unlock (&slot->lock);
  return res;
}

void
eri_live_thread_futex__requeue (struct eri_live_thread_futex *th_ftx,
			struct eri_live_thread_futex__requeue_args *args)
{
  eri_log (th_ftx->log, "enter requeue\n");
  struct eri_live_thread_futex_group *group = th_ftx->group;
  uint64_t *user_addr = args->user_addr;
  struct eri_syscall_futex_requeue_record *rec = args->rec;

  struct slot *slot[2];
  lock_slot2 (group, user_addr, slot);

  struct futex *futex[] = {
    futex_rbt_get (slot[0], user_addr, ERI_RBT_EQ),
    futex_rbt_get (slot[1], user_addr + 1, ERI_RBT_EQ)
  };

  rec->cmp = args->cmp;

  uint64_t res;
  if (args->cmp
      && (res = load_test_user (th_ftx, user_addr[0],
				 &rec->atomic, args->cmp_arg)))
    goto out;

  if (! futex[0]) goto out;

  int32_t requeue_num = args->requeue_num;
  struct eri_mtpool *pool = group->pool;

  eri_log (th_ftx->log, "requeue wake %lx\n", futex[0]);
  res = wake (th_ftx->log, futex[0], args->wake_num, -1);
  eri_log (th_ftx->log, "requeue wake result %lx\n", res);
  if (may_remove_free (th_ftx->log, pool, slot[0], futex[0])
      || eri_syscall_is_error (res)
      || slot[0] == slot[1] || requeue_num <= 0)
    goto out;

  if (! futex[1]) futex[1] = create (pool, slot[1], user_addr[1]);

  int32_t i = requeue_num;
  struct waiter *w, *nw;
  ERI_LST_FOREACH_SAFE (waiter, futex[0], w, nw)
    {
      waiter_lst_remove (futex[0], w);
      waiter_lst_append (futex[1], w);

      if (--i == 0) break;
    }
  may_remove_free (th_ftx->log, pool, slot[0], futex[0]);

  if (args->cmp && ! eri_syscall_is_error (res)) res += requeue_num - i;

out:
  unlock_slot2 (slot);
  eri_log (th_ftx->log, "leave requeue\n");
  rec->res.result = res;
}

static uint8_t
wake_op_pass_cmp (int32_t old, uint8_t op, int32_t arg)
{
  switch (op)
    {
    case ERI_FUTEX_OP_CMP_EQ: return old == arg;
    case ERI_FUTEX_OP_CMP_NE: return old != arg;
    case ERI_FUTEX_OP_CMP_LT: return old < arg;
    case ERI_FUTEX_OP_CMP_LE: return old <= arg;
    case ERI_FUTEX_OP_CMP_GT: return old > arg;
    case ERI_FUTEX_OP_CMP_GE: return old >= arg;
    default: eri_assert_unreachable ();
    }
}

void
eri_live_thread_futex__wake_op (struct eri_live_thread_futex *th_ftx,
			struct eri_live_thread_futex__wake_op_args *args)
{
  struct eri_live_thread_futex_group *group = th_ftx->group;
  uint64_t *user_addr = args->user_addr;
  struct eri_syscall_futex_record *rec = args->rec;

  struct slot *slot[2];
  lock_slot2 (group, user_addr, slot);

  struct futex *futex[] = {
    futex_rbt_get (slot[0], user_addr, ERI_RBT_EQ),
    futex_rbt_get (slot[1], user_addr + 1, ERI_RBT_EQ)
  };

  int32_t old;
  struct eri_live_atomic_args at_args = {
    th_ftx->log, th_ftx->entry,
    eri_syscall_futex_atomic_code_from_wake_op (args->op),
    (void *) user_addr[1], sizeof (int32_t), &rec->atomic, &old,
    args->op == ERI_FUTEX_OP_ANDN ? ~args->op_arg : args->op_arg
  };
  eri_live_atomic (group->atomic, &at_args);

  uint64_t res;

  if (! rec->atomic.ok) { res = ERI_EFAULT; goto out; }

  res = wake_free (th_ftx, slot[0], futex[0], args->wake_num[0], -1);

  if (eri_syscall_is_error (res)
      || ! wake_op_pass_cmp (old, args->cmp, args->cmp_arg)) goto out;

  res += wake_free (th_ftx, slot[1], futex[1], args->wake_num[1], -1);

out:
  unlock_slot2 (slot);
  rec->res.result = res;
}
