#include "lib/loop.h"

#include "lib/syscall.h"
#include "lib/lock.h"
#include "lib/util.h"
#include "lib/list.h"

struct evt
{
  ERI_LST_NODE_FIELDS (evt)

  void (*fn) (void *);
  void *data;
};

struct evts
{
  ERI_LST_LIST_FIELDS (evt)
};

ERI_DEFINE_LIST (static, evt, struct evts, struct evt)

struct eri_loop
{
  struct eri_mtpool *pool;

  uint32_t version;

  int32_t evts_lock;
  struct evts *pending;
  struct evts evts[2];
};

struct eri_loop *
eri_loop_create (uint8_t mt, struct eri_mtpool *pool)
{
  struct eri_loop *l = eri_assert_ccalloc (mt, pool, sizeof *l);
  l->pool = pool;
  l->pending = &l->evts[0];
  ERI_LST_INIT_LIST (evt, &l->evts[0]);
  ERI_LST_INIT_LIST (evt, &l->evts[1]);
  return l;
}

void *
eri_loop_loop (struct eri_loop *l)
{
  uint32_t version = 0;
  while (1)
    {
      int64_t res = ERI_SYSCALL (futex, &l->version, ERI_FUTEX_WAIT_PRIVATE, version, 0);
      eri_assert (! ERI_SYSCALL_ERROR_P (res) || -res == ERI_EAGAIN);

      uint32_t v;
      while ((v = eri_atomic_load (&l->version)) != version)
	{
	  struct evts *evts = l->pending;
	  eri_lock (&l->evts_lock);
	  l->pending = evts == &l->evts[0] ? &l->evts[1] : &l->evts[0];
	  eri_unlock (&l->evts_lock);

	  struct evt *e, *ne;
	  ERI_LST_FOREACH_SAFE (evt, evts, e, ne)
	    {
	      evt_lst_remove (evts, e);
	      void (*fn) (void *) = e->fn;
	      void *data = e->data;
	      eri_assert_mtfree (l->pool, e);

	      if (fn == 0)
		{
		  eri_assert_mtfree (l->pool, l);
		  return data;
		}

	      fn (data);
	    }
	}
      version = v;
    }
}

void
eri_loop_exit (struct eri_loop *l, void *data)
{
  eri_loop_trigger (l, 0, data);
}

void
eri_loop_trigger (struct eri_loop *l, void (*fn) (void *), void *data)
{
  struct evt *e = eri_assert_mtmalloc (l->pool, sizeof *e);
  e->fn = fn;
  e->data = data;

  eri_lock (&l->evts_lock);
  evt_lst_append (l->pending, e);
  eri_unlock (&l->evts_lock);

  eri_atomic_inc (&l->version);
  ERI_ASSERT_SYSCALL (futex, &l->version, ERI_FUTEX_WAKE_PRIVATE, 1);
}
