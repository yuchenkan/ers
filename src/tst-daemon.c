#include <pthread.h>

#include "daemon.h"
#include "lib/util.h"
#include "lib/malloc.h"

static void *
fn (void *data)
{
  eri_assert (eri_loop_loop (data) == (void *) 1);
  return 0;
}

static void
sti (void *data)
{
  *(int *) data = 1;
}

int
main (void)
{
  char buf[2 * 1024 * 1024];
  struct eri_mtpool p = { 0 };
  eri_assert (eri_init_pool (&p.pool, buf, sizeof buf) == 0);
  struct eri_loop *l = eri_loop_create (&p);

  int i[6] = { 0 };
  eri_loop_trigger (l, sti, i);

  pthread_t th;
  eri_assert (pthread_create (&th, 0, fn, l) == 0);

  int j;
  for (j = 1; j < eri_length_of (i); ++j) eri_loop_trigger (l, sti, i + j);

  eri_loop_exit (l, (void *) 1);

  eri_assert (pthread_join (th, 0) == 0);

  for (j = 0; j < eri_length_of (i); ++j) eri_assert (i[j] == 1);
  eri_assert (eri_fini_pool (&p.pool) == 0);
  return 0;
}
