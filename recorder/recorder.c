#include "recorder.h"
#include "thread.h"

#include "lib/util.h"
#include "lib/malloc.h"
#include "lib/printf.h"

struct ers_internal
{
  char buf[64 * 1024 * 1024];
  struct pool pool;
};

static void
ers_init_process (struct ers_recorder *self)
{
  eri_assert (eri_init_pool (&self->internal->pool, self->internal->buf, sizeof self->internal->buf) == 0);
  self->initialized = 1;
}

static struct ers_thread *
ers_init_thread (struct ers_recorder *self)
{
  struct ers_thread *th;
  eri_assert (eri_malloc (&self->internal->pool, sizeof *th, &th) == 0);
  th->external = (long) th + 1234;
  eri_printf ("init thread %lx\n", th);
  return th;
}

static void
ers_fini_thread (struct ers_recorder *self, struct ers_thread *th)
{
  eri_printf ("fini thread %lx\n", th);
  eri_assert (eri_free (&self->internal->pool, th) == 0);
}

static void
ers_debug (struct ers_recorder *self, struct ers_thread* th, const char *text)
{
  eri_printf ("debug %lx %s\n", th, text);
}

static void
ers_lock (struct ers_recorder *self, struct ers_thread* th, void *mem, int size, int mo)
{
}

static void
ers_unlock (struct ers_recorder *self, void *mem)
{
}

static void
ers_barrier (struct ers_recorder *self, struct ers_thread *th, int mo)
{
}

static struct ers_internal internal;

static struct ers_recorder recorder = {

  0,
  ers_init_process,
  ers_init_thread,
  ers_fini_thread,
  ers_debug,
  ers_lock,
  ers_unlock,
  ers_barrier,

  &internal
};

__attribute__ ((visibility ("default")))
struct ers_recorder *
ers_get_recorder (void)
{
  return &recorder;
}
