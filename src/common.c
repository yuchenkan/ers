#include "common.h"
#include "lib/lock.h"
#include "lib/loop.h"

struct daemon
{
  struct eri_daemon daemon;

  int32_t alive;
  struct eri_mtpool *pool;
  uint8_t *stack;
  struct eri_loop *loop;
};

void
eri_daemon_loop (struct daemon *da)
{
  eri_loop_loop (da->loop);
};

int32_t eri_daemon_clone (uint8_t *stack_top, int32_t *alive,
			  struct daemon *da);

struct eri_daemon *
eri_daemon_start (uint8_t mt, struct eri_mtpool *pool, uint64_t stack_size)
{
  struct daemon *da = eri_assert_cmalloc (mt, pool, sizeof *da);
  da->alive = 1;
  da->pool = pool;
  da->stack = eri_assert_cmalloc (mt, pool, stack_size);
  da->loop = eri_loop_create (mt, pool);
  da->daemon.pid = eri_daemon_clone (da->stack + stack_size, &da->alive, da);
  return (void *) da;
}

void
eri_daemon_invoke (struct eri_daemon *daemon,
		   void (*fn) (void *), void *data)
{
  struct daemon *da = (void *) daemon;
  eri_loop_trigger (da->loop, fn, data);
}

void
eri_daemon_stop (uint8_t mt, struct eri_daemon *daemon)
{
  struct daemon *da = (void *) daemon;
  eri_loop_exit (da->loop, 0);
  eri_lock (&da->alive);
  eri_assert_cfree (mt, da->pool, da->stack);
  eri_assert_cfree (mt, da->pool, da);
}
