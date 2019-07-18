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

  struct eri_live_thread_futex *pi;

  ERI_LST_NODE_FIELDS (waiter)
};

struct eri_live_futex
{
  uint64_t user_addr;

  /* TODO: priority */
  ERI_LST_LIST_FIELDS (waiter)

  struct eri_live_thread_futex *owner;
  ERI_LST_NODE_FIELDS (pi)

  ERI_RBT_NODE_FIELDS (futex, struct eri_live_futex)
};

ERI_DEFINE_LIST (static, waiter, struct eri_live_futex, struct waiter)

struct slot
{
  eri_lock_t lock;

  ERI_RBT_TREE_FIELDS (futex, struct eri_live_futex)
};

ERI_DEFINE_RBTREE (static, futex, struct slot,
		   struct eri_live_futex, uint64_t, eri_less_than)

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

  int32_t tid;
  int32_t user_tid;

  eri_lock_t pi_lock;
  ERI_LST_LIST_FIELDS (pi)

  struct eri_robust_list_head *user_robust_list;
};

ERI_DEFINE_LIST (static, pi,
		 struct eri_live_thread_futex, struct eri_live_futex)


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
  th_ftx->pi_lock = 0;
  ERI_LST_INIT_LIST (pi, th_ftx);
  th_ftx->user_robust_list = 0;
  return th_ftx;
}

void
eri_live_thread_futex__set_tid (struct eri_live_thread_futex *th_ftx,
				int32_t tid, int32_t user_tid)
{
  th_ftx->tid = tid;
  th_ftx->user_tid = user_tid;
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
may_remove_free (struct eri_mtpool *pool,
		 struct slot *slot, struct eri_live_futex *futex)
{
  if (waiter_lst_get_size (futex)) return 0;
  if (futex->owner)
    {
      eri_assert_lock (&futex->owner->pi_lock);
      pi_lst_remove (futex->owner, futex);
      eri_assert_unlock (&futex->owner->pi_lock);
    }
  futex_rbt_remove (slot, futex);
  eri_assert_mtfree (pool, futex);
  return 1;
}

static uint8_t
remove_waiter (struct eri_mtpool *pool, struct slot *slot,
	       struct eri_live_futex *futex, struct waiter *waiter)
{
  waiter_lst_remove (futex, waiter);
  return may_remove_free (pool, slot, futex);
}

static uint64_t
wake (eri_file_t log, struct eri_live_futex *futex,
      int32_t max, uint32_t mask)
{
  int32_t i = max;
  struct waiter *w, *nw;
  ERI_LST_FOREACH_SAFE (waiter, futex, w, nw)
    {
      /* XXX: seems kernel may wake up at least one waiter */
      if (i <= 0) break;

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
	   struct eri_live_futex *futex, int32_t max, uint32_t mask)
{
  if (! futex) return 0;

  uint64_t res = wake (th_ftx->log, futex, max, mask);
  may_remove_free (th_ftx->group->pool, slot, futex);
  return res;
}

static uint64_t
check (struct eri_live_futex *futex)
{
  return futex && futex->owner ? ERI_EINVAL : 0;
}

static uint64_t
check2 (struct eri_live_futex **futex)
{
  return check (futex[0]) ? : check (futex[1]);
}

static uint64_t
check_pi (struct eri_live_futex *futex)
{
  return futex && ! futex->owner ? ERI_EINVAL : 0;
}

static struct eri_live_futex *
create (struct eri_mtpool *pool, struct slot *slot, uint64_t user_addr,
	struct eri_live_thread_futex *owner)
{
  struct eri_live_futex *futex = eri_assert_mtmalloc (pool, sizeof *futex);
  futex->user_addr = user_addr;
  ERI_LST_INIT_LIST (waiter, futex);
  futex->owner = owner;
  futex_rbt_insert (slot, futex);
  if (owner) pi_lst_append (owner, futex);
  return futex;
}

struct eri_live_futex *
eri_live_thread_futex__create_futex_pi (struct eri_live_thread_futex *th_ftx,
					uint64_t user_addr)
{
  struct eri_live_thread_futex_group *group = th_ftx->group;
  return create (group->pool, get_slot (group, user_addr), user_addr, th_ftx);
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
  rec->access = 0;

  struct slot *slot = lock_slot (group, user_addr);

  uint64_t res;
  struct eri_live_futex *futex = futex_rbt_get (slot, &user_addr, ERI_RBT_EQ);
  if ((res = check (futex))) goto unlock_out;

  rec->access = 1;
  if ((res = load_test_user (th_ftx, user_addr, &rec->atomic, args->cmp_arg)))
    goto unlock_out;

   if (! futex) futex = create (group->pool, slot, user_addr, 0);

  struct waiter waiter = { 1, args->mask };
  waiter_lst_append (futex, &waiter);
  eri_assert_unlock (&slot->lock);

  struct eri_sys_syscall_args sys_args = {
    __NR_futex,
    { (uint64_t) &waiter.lock,
      (args->abs_time ? ERI_FUTEX_WAIT_BITSET_PRIVATE : ERI_FUTEX_WAIT_PRIVATE)
	| (args->clock_real_time ? ERI_FUTEX_CLOCK_REALTIME : 0), 1,
      (uint64_t) args->timeout }
  };
  do
    res = eri_entry__sys_syscall_interruptible (th_ftx->entry, &sys_args);
  while (res == 0 && eri_atomic_load (&waiter.lock, 1));

  if (res == ERI_EAGAIN) res = 0;
  else if (eri_syscall_is_error (res))
    {
      eri_lassert (th_ftx->log, res == ERI_EINTR || res == ERI_ETIMEDOUT);
      eri_assert_lock (&slot->lock);
      if (! waiter.lock) res = 0;
      else remove_waiter (group->pool, slot, futex, &waiter);
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
  struct eri_live_futex *futex = futex_rbt_get (slot, &user_addr, ERI_RBT_EQ);
  uint64_t res = check (futex) ? : wake_free (th_ftx, slot, futex, max, mask);
  eri_assert_unlock (&slot->lock);
  return res;
}

void
eri_live_thread_futex__requeue (struct eri_live_thread_futex *th_ftx,
			struct eri_live_thread_futex__requeue_args *args)
{
  struct eri_live_thread_futex_group *group = th_ftx->group;
  uint64_t *user_addr = args->user_addr;
  struct eri_syscall_futex_requeue_record *rec = args->rec;

  rec->access = 0;
  rec->pi = 0;

  struct slot *slot[2];
  lock_slot2 (group, user_addr, slot);

  struct eri_live_futex *futex[] = {
    futex_rbt_get (slot[0], user_addr, ERI_RBT_EQ),
    futex_rbt_get (slot[1], user_addr + 1, ERI_RBT_EQ)
  };

  uint64_t res;
#if 0
  if (cmd != ERI_FUTEX_CMP_REQUEUE_PI)
    {
      if ((rec.res.result = syscall_futex_check (futex[0]))) goto out;
      if ((rec.res.result = syscall_futex_check_pi (futex[1]))) goto out;
    }
  else if ((rec.res.result = syscall_futex_check2 (futex))) goto out;
#endif
  if ((res = check2 (futex))) goto out;

  if (args->cmp)
    {
      rec->access = 1;
      if ((res = load_test_user (th_ftx, user_addr[0],
				 &rec->atomic, args->cmp_arg)))
	goto out;
    }

  if (! futex[0]) goto out;

  int32_t requeue_num = args->requeue_num;
  struct eri_mtpool *pool = group->pool;

  res = wake (th_ftx->log, futex[0], args->wake_num, -1);
  if (may_remove_free (pool, slot[0], futex[0]) || eri_syscall_is_error (res)
      || slot[0] == slot[1] || requeue_num <= 0)
    goto out;

  if (! futex[1]/* && cmd != ERI_FUTEX_CMP_REQUEUE_PI */)
    futex[1] = create (pool, slot[1], user_addr[1], 0);

#if 0
  struct eri_buf pi;
  if (cmd == ERI_FUTEX_CMP_REQUEUE_PI)
    eri_assert_buf_mtpool_init (&pi, pool, eri_min (val2, 32),
			sizeof (struct eri_syscall_futex_requeue_pi_record));
#endif

  int32_t i = requeue_num;
  struct waiter *w, *nw;
  ERI_LST_FOREACH_SAFE (waiter, futex[0], w, nw)
    {
      waiter_lst_remove (futex[0], w);
      waiter_lst_append (futex[1], w);
#if 0
      if (cmd != ERI_FUTEX_CMP_REQUEUE_PI)
	futex_waiter_lst_append (futex[1], w);
      else
	{
	  int32_t next = w->pi->user_tid;

	  struct eri_syscall_futex_requeue_pi_record r = { next };
	  int32_t owner;
	  uint64_t res = syscall_futex_try_lock_pi (th, user_addr[1], next,
						    &owner, &r.atomic);
	  eri_assert_buf_append (&pi, &r, 1);
	  if (eri_syscall_is_error (res) || (res == 1 && futex[1]))
	    {
	      rec.res.result = res == 1 ? ERI_EINVAL : res;
	      break;
	    }
	  else if (res == 1)
	    {
	      if (futex[1])
		{
		  rec.res.result = ERI_EINVAL;
		  break;
		}

	      w->lock_pi = w->pi->tid;
	      eri_lassert_syscall (th->log.file, futex, &w->lock,
				   ERI_FUTEX_WAKE_PRIVATE, 1);
	    }
	  else
	    {
	      int32_t tid;
	      if ((res = create_set_futex_pi_owner (th, slot[1],
				user_addr[1], owner, futex + 1, &tid)))
		{
		  rec.res.result = res;
		  break;
		}

	      w->lock_pi = tid;
	      futex_pi_waiter_lst_append (futex[1], w);
	      res = eri_syscall (futex, &w->lock, ERI_FUTEX_CMP_REQUEUE_PI,
				 1, 1, &w->lock_pi, 1);
	      if (eri_syscall_is_error (res))
		{
		  rec.res.result = res;
		  break;
		}
	    }
	}
#endif
      if (--i == 0) break;
    }
  may_remove_free (pool, slot[0], futex[0]);

  if (args->cmp/* && ! eri_syscall_is_error (res) */) res += requeue_num - i;

out:
  unlock_slot2 (slot);
  rec->res.result = res;

#if 0
  if (cmd == ERI_FUTEX_CMP_REQUEUE_PI) rec.pi = pi.n;
#endif
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
  rec->access = 0;

  struct slot *slot[2];
  lock_slot2 (group, user_addr, slot);

  struct eri_live_futex *futex[] = {
    futex_rbt_get (slot[0], user_addr, ERI_RBT_EQ),
    futex_rbt_get (slot[1], user_addr + 1, ERI_RBT_EQ)
  };

  uint64_t res;
  if ((res = check2 (futex))) goto out;

  rec->access = 1;
  int32_t old;
  struct eri_live_atomic_args at_args = {
    th_ftx->log, th_ftx->entry,
    eri_syscall_futex_atomic_code_from_wake_op (args->op),
    (void *) user_addr[1], sizeof (int32_t), &rec->atomic, &old,
    args->op == ERI_FUTEX_OP_ANDN ? ~args->op_arg : args->op_arg
  };
  eri_live_atomic (group->atomic, &at_args);

  if (! rec->atomic.ok) { res = ERI_EFAULT; goto out; }

  res = wake_free (th_ftx, slot[0], futex[0], args->wake_num[0], -1);

  if (eri_syscall_is_error (res)
      || ! wake_op_pass_cmp (old, args->cmp, args->cmp_arg)) goto out;

  res += wake_free (th_ftx, slot[1], futex[1], args->wake_num[1], -1);

out:
  unlock_slot2 (slot);
  rec->res.result = res;
}

static uint64_t
try_lock_pi (struct eri_live_thread_futex *th_ftx, uint64_t user_addr,
	     int32_t user_next, uint8_t try, int32_t *user_owner,
	     struct eri_atomic_record *rec)
{
  struct eri_live_atomic *atomic = th_ftx->group->atomic;
  struct eri_entry *entry = th_ftx->entry;

  struct eri_pair idx = eri_live_atomic_lock (atomic, user_addr,
					      sizeof (int32_t));
  if (! eri_entry__test_access (entry, user_addr, 0))
    {
      eri_live_atomic_unlock (atomic, &idx, 0);
      rec->ok = 0;
      return ERI_EFAULT;
    }

  int32_t old = eri_atomic_futex_lock_pi ((void *) user_addr, user_next, try);

  eri_entry__reset_test_access (entry);

  rec->ok = 1;
  rec->ver = eri_live_atomic_unlock (atomic, &idx, 1);

  if ((old & ~ERI_FUTEX_OWNER_DIED) == 0) return 1;

  *user_owner = old & ERI_FUTEX_TID_MASK;
  return 0;
}

void
eri_live_thread_futex__lock_pi (struct eri_live_thread_futex *th_ftx,
			struct eri_live_thread_futex__lock_pi_args *args)
{
  struct eri_live_thread_futex_group *group = th_ftx->group;
  uint64_t user_addr = args->user_addr;
  struct eri_syscall_futex_lock_pi_record *rec = args->rec;
  rec->access = 0;

  struct slot *slot = lock_slot (group, user_addr);

  struct eri_live_futex *futex = futex_rbt_get (slot, &user_addr, ERI_RBT_EQ);

  uint64_t res;
  if ((res = check_pi (futex))) goto out;

  rec->access = 1;

  if (! futex)
    {
      int32_t user_owner;
      res = try_lock_pi (th_ftx, user_addr, th_ftx->user_tid, args->try,
			 &user_owner, rec->atomic);

      if (res == 1) { res = 0; goto out; }
      else if (eri_syscall_is_error (res)) goto out;
      else if (user_owner == th_ftx->user_tid)
	{ res = ERI_EDEADLK; goto out; }
      else if (args->try) { res = ERI_EAGAIN; goto out; }

      if ((res = eri_live_signal_thread__create_futex_pi (args->sig_th,
					user_owner, user_addr, &futex)))
	goto out;
    }
  else if (futex->owner == th_ftx) { res = ERI_EDEADLK; goto out; }
  else if (args->try) { res = ERI_EAGAIN; goto out; }

  struct waiter waiter = { futex->owner->tid, -1, th_ftx };
  waiter_lst_append (futex, &waiter);

retry:
  eri_assert_unlock (&slot->lock);

  struct eri_sys_syscall_args sys_args = {
    __NR_futex,
    { (uint64_t) &waiter.lock, ERI_FUTEX_LOCK_PI_PRIVATE, 0,
      (uint64_t) args->timeout }
  };
  res = eri_entry__sys_syscall_interruptible (th_ftx->entry, &sys_args);

  eri_assert_lock (&slot->lock);

  futex = futex_rbt_get (slot, &user_addr, ERI_RBT_EQ);
  if (! futex || futex->owner == th_ftx) res = 0;

  if (eri_syscall_is_ok (res))
    {
      waiter.lock = futex->owner->tid;
      goto retry;
    }
  else if (remove_waiter (group->pool, slot, futex, &waiter))
    {
      rec->access = 2;
      struct eri_live_atomic_args at_args = {
	th_ftx->log, th_ftx->entry, ERI_OP_ATOMIC_AND, (void *) user_addr,
	sizeof (int32_t), rec->atomic + 1, 0, ~ERI_FUTEX_WAITERS
      };
      eri_live_atomic (group->atomic, &at_args);
    }

out:
  eri_assert_unlock (&slot->lock);
  rec->res.result = res;
}

static uint64_t
unlock (struct eri_live_thread_futex *th_ftx, uint64_t user_addr,
	int32_t user_next, uint8_t wait, struct eri_atomic_record *rec)
{
  struct eri_live_atomic *atomic = th_ftx->group->atomic;
  struct eri_pair idx = eri_live_atomic_lock (atomic, user_addr,
					      sizeof (int32_t));
  if (! eri_entry__test_access (th_ftx->entry, user_addr, 0))
    {
      eri_live_atomic_unlock (atomic, &idx, 0);
      rec->ok = 0;
      return 1;
    }

  uint8_t valid = eri_atomic_futex_unlock_pi ((void *) user_addr,
				th_ftx->user_tid, user_next, wait);
  eri_entry__reset_test_access (th_ftx->entry);

  rec->ok = 1;
  rec->ver = eri_live_atomic_unlock (atomic, &idx, 1);
  return valid ? 0 : ERI_EINVAL;

}

static void
wake_pi (struct eri_live_thread_futex *th_ftx, struct slot *slot,
	 struct eri_live_futex *futex, struct waiter *waiter)
{
  if (! remove_waiter (th_ftx->group->pool, slot, futex, waiter))
    {
      futex->owner = waiter->pi;
      eri_assert_lock (&waiter->pi->pi_lock);
      pi_lst_append (futex->owner, futex);
      eri_assert_unlock (&waiter->pi->pi_lock);
    }

  eri_lassert_syscall (th_ftx->log, futex, &waiter->lock,
		       ERI_FUTEX_UNLOCK_PI_PRIVATE);

  ERI_LST_FOREACH (waiter, futex, waiter)
    eri_lassert_syscall (th_ftx->log, futex, &waiter->lock,
			 ERI_FUTEX_UNLOCK_PI_PRIVATE);
}

void
eri_live_thread_futex__unlock_pi (struct eri_live_thread_futex *th_ftx,
	uint64_t user_addr, struct eri_syscall_futex_unlock_pi_record *rec)
{
  struct eri_live_thread_futex_group *group = th_ftx->group;
  rec->access = 0;

  struct slot *slot = lock_slot (group, user_addr);

  struct eri_live_futex *futex = futex_rbt_get (slot, &user_addr, ERI_RBT_EQ);

  uint64_t res;
  if ((res = check_pi (futex))) goto out;

  if (futex && futex->owner != th_ftx) { res = ERI_EPERM; goto out; }

  rec->access = 1;

  struct waiter *waiter = futex ? waiter_lst_get_first (futex) : 0;

  rec->user_next = waiter ? waiter->pi->user_tid : 0;
  rec->wait = futex ? waiter_lst_get_size (futex) > 1 : 0;

  if ((res = unlock (th_ftx, user_addr, rec->user_next,
		     rec->wait, &rec->atomic))) goto out;

  if (waiter) wake_pi (th_ftx, slot, futex, waiter);

out:
  eri_assert_unlock (&slot->lock);
  rec->res.result = res;
}
