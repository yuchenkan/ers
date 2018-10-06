#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <assert.h>
#include <time.h>

static unsigned
ran (unsigned r)
{
  return (r * 1103515245u + 12345u) & 0x7fffffffu;
}

static void *f (void *p)
{
  unsigned r = (unsigned) (long) p;
  void *o = NULL;
  int i;
  for (i = 0; i < 64; ++i)
    {
      r = ran (r);
      if (o) free (o);
      size_t s = r % (64 * 1024 * 1024) + 1;
      // fprintf (stderr, "malloc %u\n", s);
      o = malloc (s);
    }
  free (o);
  return NULL;
}

int main ()
{
  unsigned r = (unsigned) time (NULL);
  pthread_t ths[16];
  int i;
  for (i = 0; i < sizeof ths / sizeof ths[0]; ++i)
    {
      r = ran (r);
      assert (pthread_create (ths + i, NULL, f, (void *) (long) r) == 0);
    }

  for (i = 0; i < sizeof ths / sizeof ths[0]; ++i)
    {
      fprintf (stderr, "joining !!!!!!!!!!!!!!!!!!!!!\n");
      assert (pthread_join (ths[i], NULL) == 0);
    }

  fprintf (stderr, "exiting !!!!!!!!!!!!!!!!!!!!!\n");
  return 0;
}
