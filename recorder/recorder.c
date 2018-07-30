#include <stdio.h>
#include <stdlib.h>

#include "recorder.h"
#include "thread.h"

#define NO_UNISTD
#include "../common/common.h"

static void ers_init_process (struct ers_recorder* self);
static struct ers_thread * ers_init_thread (struct ers_recorder *self);
static void ers_fini_thread (struct ers_recorder *self, struct ers_thread *th);
static void ers_debug (struct ers_recorder *self, struct ers_thread* th, const char *text);

static struct ers_recorder recorder = {
  0,
  ers_init_process,
  ers_init_thread,
  ers_fini_thread,
  ers_debug
};

static void
ers_init_process (struct ers_recorder *self)
{
  self->initialized = 1;
}

static struct ers_thread *
ers_init_thread (struct ers_recorder *self)
{
  struct ers_thread *th = malloc (sizeof *th);
  th->external = (long) th + 1234;
  printf ("init thread %p\n", th);
  return th;
}

static void
ers_fini_thread (struct ers_recorder *self, struct ers_thread *th)
{
  printf ("fini thread %p\n", th);
  free (th);
}

static void
ers_debug (struct ers_recorder *self, struct ers_thread* th, const char *text)
{
  it_printf ("debug %lx %s\n", th, text);
}

struct ers_recorder *
ers_get_recorder (void)
{
  return &recorder;
}
