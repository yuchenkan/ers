#include "recorder.h"
#include "thread.h"

#include "lib/util.h"
#include "lib/env.h"
#include "lib/lock.h"
#include "lib/malloc.h"
#include "lib/printf.h"
#include "lib/rbtree.h"

struct atomic_lock
{
  void *mem;
  size_t size;

  ERS_RBT_NODE_FIELDS (struct atomic_lock)
};

struct atomic_locks
{
  ERS_RBT_TREE_FIELDS (struct atomic_lock)
  int lock;
};

ERS_DEFINE_RBTREE (static, atomic, struct atomic_locks, struct atomic_lock, void, ers_less_than)

struct ers_internal
{
  char buf[64 * 1024 * 1024];
  struct ers_pool pool;

  const char *path;

  struct atomic_locks atomic_locks;
};

static void
ers_init_process (struct ers_recorder *self)
{
  ers_assert (ers_init_pool (&self->internal->pool, self->internal->buf, sizeof self->internal->buf) == 0);
  ers_assert (ers_get_env ("ERS_RECORD_PATH", &self->internal->path) == 0);

  self->initialized = 1;
}

static struct ers_thread *
ers_init_thread (struct ers_recorder *self)
{
  struct ers_thread *th;
  ers_assert (ers_calloc (&self->internal->pool, sizeof *th, (void **) &th) == 0);
  th->recorder = self;
  th->external = (long) th + 1234;
  ers_printf ("init thread %lx\n", th);
  return th;
}

static void
ers_fini_thread (struct ers_thread *th)
{
  ers_printf ("fini thread %lx\n", th);
  ers_assert (ers_free (&th->recorder->internal->pool, th) == 0);
}

static long
ers_syscall (struct ers_thread *th, int nr, long a1,
	     long a2, long a3, long a4, long a5, long a6)
{
  ers_printf ("ers_syscall %lx\n", th);
  return -1;
}

static void
ers_atomic_lock (struct ers_thread* th, void *mem, int size, int mo)
{
  struct atomic_locks *locks = &th->recorder->internal->atomic_locks;
  ers_lock (&locks->lock);

  ers_printf ("atomic lock %lx %lx %u %u\n", th, mem, size, mo);
  struct atomic_lock *lock = atomic_get (locks, mem, ERS_RBT_EQ | ERS_RBT_LT);
  if (! lock || (char *) lock->mem + lock->size <= (char *) mem)
    {
      ers_assert (ers_calloc (&th->recorder->internal->pool, sizeof *lock, (void **) &lock) == 0);
      lock->mem = mem;
      lock->size = size;
      atomic_insert (locks, lock);
    }
  else ers_assert (lock->mem == mem && lock->size == size);
}

static void
ers_atomic_unlock (struct ers_thread *th, void *mem)
{
  ers_printf ("atomic unlock %lx\n", mem);
  ers_unlock (&th->recorder->internal->atomic_locks.lock);
}

static void
ers_atomic_barrier (struct ers_thread *th, int mo)
{
  ers_printf ("atomic barrier %lx %u\n", th, mo);
}

static void
ers_debug (struct ers_thread* th, const char *text)
{
  ers_printf ("debug %lx %s\n", th, text);
}

static struct ers_internal internal;

static struct ers_recorder recorder = {

  0,
  ers_init_process,
  ers_init_thread,
  ers_fini_thread,
  ers_syscall,
  ers_atomic_lock,
  ers_atomic_unlock,
  ers_atomic_barrier,
  ers_debug,

  &internal
};

__attribute__ ((visibility ("default"))) struct ers_recorder *
ers_get_recorder (void)
{
  return &recorder;
}
