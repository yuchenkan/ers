#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>

static void *f (void *p)
{
  fprintf (stderr, "xxx\n");
  return NULL;
}

int main ()
{
  pthread_t thread;
  int r = pthread_create (&thread, NULL, f, NULL);
  fprintf (stderr, "%d\n", r);
  assert (r == 0);
  fprintf (stderr, "yyy\n");

  assert (pthread_join (thread, NULL) == 0);
  fprintf (stderr, "zzz\n");
  return 0;
}
