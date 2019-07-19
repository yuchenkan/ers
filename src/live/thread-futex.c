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

  struct eri_live_thread_futex *next_pi_owner;

  uint64_t req_pi_user_addr;
  struct eri_live_futex *req_pi;

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
  eri_log (log, "create thread futex %lx\n", th_ftx);
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

static void
unown_pi (struct eri_live_futex *pi)
{
  struct eri_live_thread_futex *th_ftx = pi->owner;

  pi->owner = 0;
  eri_assert_lock (&th_ftx->pi_lock);
  pi_lst_remove (th_ftx, pi);
  eri_assert_unlock (&th_ftx->pi_lock);
}

static void
own_pi (struct eri_live_thread_futex *th_ftx, struct eri_live_futex *pi)
{
  if (pi->owner) unown_pi (pi);

  pi->owner = th_ftx;
  eri_assert_lock (&th_ftx->pi_lock);
  pi_lst_append (th_ftx, pi);
  eri_assert_unlock (&th_ftx->pi_lock);
}

static uint8_t
may_remove_free (eri_file_t log, struct eri_mtpool *pool,
		 struct slot *slot, struct eri_live_futex *futex)
{
  if (waiter_lst_get_size (futex)) return 0;
  if (futex->owner) unown_pi (futex);
  eri_log (log, "remove %lx\n", futex);
  futex_rbt_remove (slot, futex);
  eri_assert_mtfree (pool, futex);
  return 1;
}

static uint8_t
remove_waiter (eri_file_t log, struct eri_mtpool *pool, struct slot *slot,
	       struct eri_live_futex *futex, struct waiter *waiter)
{
  waiter_lst_remove (futex, waiter);
  return may_remove_free (log, pool, slot, futex);
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
	   struct eri_live_futex *futex, int32_t max, uint32_t mask)
{
  if (! futex) return 0;

  uint64_t res = wake (th_ftx->log, futex, max, mask);
  may_remove_free (th_ftx->log, th_ftx->group->pool, slot, futex);
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
    res = eri_entry__sys_syscall_interruptible (th_ftx->entry, &sys_args);
  while (res == 0 && eri_atomic_load (&waiter.lock, 1));

  if (res == ERI_EAGAIN) res = 0;
  else if (eri_syscall_is_error (res))
    {
      eri_lassert (th_ftx->log, res == ERI_EINTR || res == ERI_ETIMEDOUT);
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
  struct eri_live_futex *futex = futex_rbt_get (slot, &user_addr, ERI_RBT_EQ);
  uint64_t res = check (futex) ? : wake_free (th_ftx, slot, futex, max, mask);
  eri_assert_unlock (&slot->lock);
  return res;
}

static uint64_t
try_lock (struct eri_live_thread_futex *th_ftx, uint64_t user_addr,
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

  eri_log (th_ftx->log, "try lock pi: %u\n", old);
  rec->ok = 1;
  rec->ver = eri_live_atomic_unlock (atomic, &idx, 1);

  if ((old & ~ERI_FUTEX_OWNER_DIED) == 0) return 1;

  *user_owner = old & ERI_FUTEX_TID_MASK;
  return 0;
}

static uint64_t
wait_pi (struct eri_live_thread_futex *th_ftx, struct eri_live_futex **futex,
	 struct eri_live_signal_thread *sig_th, uint64_t user_addr,
	 int32_t user_next, uint8_t try, struct waiter *waiter,
	 uint8_t *access, struct eri_atomic_record *rec)
{
  if (! *futex)
    {
      *access = 1;

      int32_t user_owner;
      /* Access user, check, and set tid (or waiters).  */
      uint64_t res = try_lock (th_ftx, user_addr, user_next, try,
			       &user_owner, rec);

      if (res) return res;
      else if (user_owner == user_next) return ERI_EDEADLK;
      else if (try) return ERI_EAGAIN;

      eri_log3 (th_ftx->log, "create futex %u\n", user_owner);
      if ((res = eri_live_signal_thread__create_futex_pi (sig_th,
					user_owner, user_addr, futex)))
	return res;
      eri_log (th_ftx->log, "post create futex %lx\n", *futex);
    }
  else if ((*futex)->owner == waiter->next_pi_owner) return ERI_EDEADLK;
  else if (try) return ERI_EAGAIN;

  return 0;
}

static uint64_t
requeue_pi (struct eri_live_thread_futex *th_ftx,
	struct eri_live_futex **futex, struct eri_live_signal_thread *sig_th,
	uint64_t user_addr, struct waiter *waiter, struct eri_buf *pi)
{
  eri_log (th_ftx->log, "requeue %lx\n", waiter);

  int32_t user_next = waiter->next_pi_owner->user_tid;

  struct eri_syscall_futex_requeue_pi_record rec = { user_next };

  uint8_t acc;
  uint64_t res = wait_pi (th_ftx, futex + 1, sig_th, user_addr, user_next,
			  0, waiter, &acc, &rec.atomic);
  if (acc) eri_assert_buf_append (pi, &rec, 1);

  if (eri_syscall_is_error (res)) return res;

  waiter_lst_remove (futex[0], waiter);
  if (res == 0)
    {
      waiter_lst_append (futex[1], waiter);

      eri_log (th_ftx->log, "waiter %lx owned by %lx %u\n", waiter,
	       futex[1], futex[1]->owner->tid);
      waiter->lock = futex[1]->owner->tid;
    }
  else waiter->lock = 0;

  waiter->req_pi = futex[1];

  eri_log (th_ftx->log, "wake %lx\n", waiter);
  eri_lassert_syscall (th_ftx->log, futex, &waiter->lock,
		       ERI_FUTEX_WAKE_PRIVATE, 1);
  return 0;
}

void
eri_live_thread_futex__requeue (struct eri_live_thread_futex *th_ftx,
			struct eri_live_thread_futex__requeue_args *args)
{
  eri_log (th_ftx->log, "enter requeue\n");
  struct eri_live_thread_futex_group *group = th_ftx->group;
  uint64_t *user_addr = args->user_addr;
  struct eri_syscall_futex_requeue_record *rec = args->rec;
  struct eri_buf *pi = args->pi;

  rec->access = 0;
  rec->pi = 0;

  struct slot *slot[2];
  lock_slot2 (group, user_addr, slot);

  struct eri_live_futex *futex[] = {
    futex_rbt_get (slot[0], user_addr, ERI_RBT_EQ),
    futex_rbt_get (slot[1], user_addr + 1, ERI_RBT_EQ)
  };

  uint64_t res;
  if (pi)
    {
      if ((res = check (futex[0]))) goto out;
      if ((res = check_pi (futex[1]))) goto out;
    }
  else if ((res = check2 (futex))) goto out;

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

  eri_log (th_ftx->log, "requeue wake %lx\n", futex[0]);
  res = wake (th_ftx->log, futex[0], args->wake_num, -1);
  eri_log (th_ftx->log, "requeue wake result %lx\n", res);
  if (may_remove_free (th_ftx->log, pool, slot[0], futex[0])
      || eri_syscall_is_error (res)
      || slot[0] == slot[1] || requeue_num <= 0)
    goto out;

  if (! futex[1] && ! pi)
    futex[1] = create (pool, slot[1], user_addr[1], 0);

  if (pi)
    eri_assert_buf_mtpool_init (pi, pool, eri_min (requeue_num, 32),
			sizeof (struct eri_syscall_futex_requeue_pi_record));

  int32_t i = requeue_num;
  struct waiter *w, *nw;
  ERI_LST_FOREACH_SAFE (waiter, futex[0], w, nw)
    {
      eri_log (th_ftx->log, "requeue pi eq %lx %lx, %lx %lx\n",
	       pi, w->next_pi_owner, w->req_pi_user_addr, user_addr[1]);
      if (! pi != ! w->next_pi_owner
	  || (pi && w->req_pi_user_addr != user_addr[1]))
	{ res = ERI_EINVAL; break; }

      uint64_t r;
      if (! pi)
	{
	  waiter_lst_remove (futex[0], w);
	  waiter_lst_append (futex[1], w);
	}
      else if ((r = requeue_pi (th_ftx, futex, args->sig_th,
				user_addr[1], w, pi)))
	{ res = r; break; }

      if (--i == 0) break;
    }
  may_remove_free (th_ftx->log, pool, slot[0], futex[0]);

  eri_log (th_ftx->log, "pre requeu result: %lx\n", res);
  if (args->cmp && ! eri_syscall_is_error (res)) res += requeue_num - i;
  eri_log (th_ftx->log, "requeu result: %lx\n", res);

out:
  unlock_slot2 (slot);
  eri_log (th_ftx->log, "leave requeue\n");
  if (pi) rec->pi = pi->o;
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

uint64_t
lock_pi (struct eri_live_thread_futex *th_ftx, struct slot *slot,
	 struct eri_live_futex *futex,
	 struct waiter *waiter, struct eri_timespec *timeout)
{
retry:
  eri_assert_unlock (&slot->lock);

  eri_log (th_ftx->log, "wait %lx\n", waiter);
  struct eri_sys_syscall_args args = {
    __NR_futex,
    { (uint64_t) &waiter->lock, ERI_FUTEX_LOCK_PI_PRIVATE, 0,
      (uint64_t) timeout }
  };
  uint64_t res = eri_entry__sys_syscall_interruptible (th_ftx->entry, &args);

  eri_log (th_ftx->log, "post wait %lx %lx\n", waiter, res);
  eri_assert_lock (&slot->lock);

  if (futex->owner == th_ftx) res = 0;
  else if (eri_syscall_is_ok (res) || res == ERI_ESRCH)
    {
      eri_log (th_ftx->log, "retry %lx\n", waiter);
      waiter->lock = futex->owner->tid;
      goto retry;
    }
  return res;
}

static uint8_t
remove_clear_waiter (struct eri_live_thread_futex *th_ftx, struct slot *slot,
		     struct eri_live_futex *futex, struct waiter *waiter,
		     uint64_t user_addr, struct eri_atomic_record *rec)
{
  struct eri_live_thread_futex_group *group = th_ftx->group;

  if (! remove_waiter (th_ftx->log, group->pool, slot, futex, waiter))
    return 0;

  struct eri_live_atomic_args at_args = {
    th_ftx->log, th_ftx->entry, ERI_OP_ATOMIC_AND, (void *) user_addr,
    sizeof (int32_t), rec, 0, ~ERI_FUTEX_WAITERS
  };
  /* Access user & clear waiters.  */
  eri_live_atomic (group->atomic, &at_args);
  return 1;
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

  struct waiter waiter = { .next_pi_owner = th_ftx };
  res = wait_pi (th_ftx, &futex, args->sig_th, user_addr, th_ftx->user_tid,
		 args->try, &waiter, &rec->access, rec->atomic);
  switch (res)
    {
    case 0:
      waiter_lst_append (futex, &waiter); 
      waiter.lock = futex->owner->tid;
      break;
    case 1: res = 0; goto out;
    default: goto out;
    }

  res = lock_pi (th_ftx, slot, futex, &waiter, args->timeout);

  if (remove_clear_waiter (th_ftx, slot, futex, &waiter,
			   user_addr, rec->atomic + 1))
    rec->access |= 2;

out:
  eri_assert_unlock (&slot->lock);
  eri_log (th_ftx->log, "post lock %lx %lx\n", user_addr, res);
  rec->res.result = res;
}

void
eri_live_thread_futex__wait_requeue_pi (
	       struct eri_live_thread_futex *th_ftx,
	       struct eri_live_thread_futex__wait_requeue_pi_args *args)
{
  struct eri_live_thread_futex_group *group = th_ftx->group;
  uint64_t *user_addr = args->user_addr;
  struct eri_syscall_futex_lock_pi_record *rec = args->rec;
  rec->access = 0;

  struct slot *slot[2];
  slot[0] = lock_slot (group, user_addr[0]);

  struct eri_live_futex *futex = futex_rbt_get (slot[0],
						user_addr, ERI_RBT_EQ);

  uint64_t res;
  if ((res = check (futex))) goto out;

  rec->access = 1;
  if ((res = load_test_user (th_ftx, user_addr[0],
			     rec->atomic, args->cmp_arg))) goto out;

  if (! futex) futex = create (group->pool, slot[0], user_addr[0], 0);

  struct waiter waiter = { 1, -1, th_ftx, user_addr[1] };
  eri_log (th_ftx->log, "new waiter: %lx\n", &waiter);
  waiter_lst_append (futex, &waiter);
  eri_assert_unlock (&slot[0]->lock);

  struct eri_sys_syscall_args sys_args = {
    __NR_futex,
    { (uint64_t) &waiter.lock,
      ERI_FUTEX_WAIT_BITSET_PRIVATE
       | (args->clock_real_time ? ERI_FUTEX_CLOCK_REALTIME : 0), 1,
      (uint64_t) args->timeout, 0, -1 }
  };
  do
    res = eri_entry__sys_syscall_interruptible (th_ftx->entry, &sys_args);
  while (res == 0 && eri_atomic_load (&waiter.lock, 1) == 1);

  lock_slot2 (group, user_addr, slot);
  eri_log (th_ftx->log, "first wake up: %lx\n", &waiter);
  if (! waiter.lock && ! waiter.req_pi)
    {
      eri_log (th_ftx->log, "first wake EAGAIN: %lx\n", &waiter);
      res = ERI_EAGAIN;
      eri_assert_unlock (&slot[0]->lock);
    }
  else if (waiter.lock == 1)
    {
      eri_lassert (th_ftx->log, ! waiter.req_pi);
      waiter_lst_remove (futex, &waiter);
      eri_assert_unlock (&slot[0]->lock);
    }
  else
    {
      eri_assert_unlock (&slot[0]->lock);

      struct eri_live_futex *pi = waiter.req_pi;
      eri_lassert (th_ftx->log, pi);
      if (pi->owner == th_ftx) res = 0;
      else res = lock_pi (th_ftx, slot[1], pi, &waiter, args->timeout);

      if (remove_clear_waiter (th_ftx, slot[1], pi, &waiter,
			       user_addr[1], rec->atomic + 1))
	rec->access |= 2;
    }

  eri_log (th_ftx->log, "leave waiter: %lx %lx %lu\n", &waiter, res, -res);
  eri_assert_unlock (&slot[1]->lock);
  rec->res.result = res;
  return;

out:
  eri_assert_unlock (&slot[0]->lock);
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
      return ERI_EFAULT;
    }

  int32_t old;
  uint8_t valid = eri_atomic_futex_unlock_pi ((void *) user_addr,
				th_ftx->user_tid, user_next, wait, &old);
  eri_entry__reset_test_access (th_ftx->entry);

  eri_log (th_ftx->log, "unlock user_tid %u %u %u %u %u\n",
	   th_ftx->user_tid, old, user_next, wait, valid);

  rec->ok = 1;
  rec->ver = eri_live_atomic_unlock (atomic, &idx, 1);
  return valid ? 0 : ERI_EINVAL;
}

static void
wake_pi (struct eri_live_thread_futex *th_ftx, struct slot *slot,
	   struct eri_live_futex *futex, struct waiter *waiter)
{
  own_pi (waiter->next_pi_owner, futex);

  struct waiter *w;
  ERI_LST_FOREACH (waiter, futex, w)
    {
      uint64_t r = eri_syscall (futex, &w->lock,
				ERI_FUTEX_UNLOCK_PI_PRIVATE);
      eri_log (th_ftx->log, "wake %lx %lx\n", w, r);
      eri_assert (eri_syscall_is_ok (r) || r == ERI_EPERM);
    }
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

  rec->user_next = waiter ? waiter->next_pi_owner->user_tid : 0;
  rec->wait = !! futex;

  eri_log (th_ftx->log, "unlock pi addr %lx next %u wait %u\n",
	   user_addr, rec->user_next, rec->wait);

  /* Access user, check & set new owner (& waiters).  */
  if ((res = unlock (th_ftx, user_addr, rec->user_next,
		     rec->wait, &rec->atomic))) goto out;

  eri_log (th_ftx->log, "post unlock pi %lx\n", user_addr);

  if (waiter) wake_pi (th_ftx, slot, futex, waiter);

out:
  eri_assert_unlock (&slot->lock);
  eri_log (th_ftx->log, "leave unlock pi %lx\n", user_addr);
  rec->res.result = res;
}
