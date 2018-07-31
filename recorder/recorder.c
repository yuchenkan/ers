#include "recorder.h"
#include "thread.h"

#include "lib/util.h"
#include "lib/malloc.h"
#include "lib/printf.h"
#include "lib/rbtree.h"

struct ers_internal
{
  char buf[64 * 1024 * 1024];
  struct ers_pool pool;
};

static void
ers_init_process (struct ers_recorder *self)
{
  ers_assert (ers_init_pool (&self->internal->pool, self->internal->buf, sizeof self->internal->buf) == 0);
  self->initialized = 1;
}

static struct ers_thread *
ers_init_thread (struct ers_recorder *self)
{
  struct ers_thread *th;
  ers_assert (ers_malloc (&self->internal->pool, sizeof *th, (void **) &th) == 0);
  th->external = (long) th + 1234;
  ers_printf ("init thread %lx\n", th);
  return th;
}

static void
ers_fini_thread (struct ers_recorder *self, struct ers_thread *th)
{
  ers_printf ("fini thread %lx\n", th);
  ers_assert (ers_free (&self->internal->pool, th) == 0);
}

static void
ers_debug (struct ers_recorder *self, struct ers_thread* th, const char *text)
{
  ers_printf ("debug %lx %s\n", th, text);
}

static void
ers_atomic_lock (struct ers_recorder *self, struct ers_thread* th, void *mem, int size, int mo)
{
}

static void
ers_atomic_unlock (struct ers_recorder *self, void *mem)
{
}

static void
ers_atomic_barrier (struct ers_recorder *self, struct ers_thread *th, int mo)
{
}

static struct ers_internal internal;

static struct ers_recorder recorder = {

  0,
  ers_init_process,
  ers_init_thread,
  ers_fini_thread,
  ers_debug,
  ers_atomic_lock,
  ers_atomic_unlock,
  ers_atomic_barrier,

  &internal
};

__attribute__ ((visibility ("default")))
struct ers_recorder *
ers_get_recorder (void)
{
  return &recorder;
}
