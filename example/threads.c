#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>

#if 0
# define EXIT_GROUP
#endif


#if 0
# define SIGNAL
#endif

#ifdef SIGNAL
#include <signal.h>
int caught = 0;
void handler (int sig)
{
  fprintf (stderr, "signal\n");
  caught = 1;
}
#endif

static void *f (void *p)
{
  int a = 123456789;
  int* i = (int *) malloc (sizeof *i);
  *i = 987654321;
  fprintf (stderr, "xxx %p %p %d\n", &a, i, getpid ());
  free (i);
#ifdef EXIT_GROUP
  syscall (231, 1);
#endif
  return NULL;
}

int main ()
{
  struct timespec spec;
  clock_gettime (CLOCK_REALTIME, &spec);
  fprintf (stderr, "%ld\n", spec.tv_sec);
  pthread_t thread;
  char ok = pthread_create (&thread, NULL, f, NULL) == 0;
  free (malloc (1));
  fprintf (stderr, "yyy %d\n", ok);
#ifdef EXIT_GROUP
  syscall (231, 0);
#endif
  if (ok) assert (pthread_join (thread, NULL) == 0);
  fprintf (stderr, "zzz\n");
#ifdef SIGNAL
  fprintf (stderr, "%p\n", handler);
  signal (SIGINT, handler);
  while (! caught) continue;
  assert (signal (SIGINT, 0) == handler);
#endif
  return 0;
}
