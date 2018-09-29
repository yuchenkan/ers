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
pthread_spinlock_t caught;
void handler (int sig)
{
  fprintf (stderr, "signal\n");
  pthread_spin_unlock (&caught);
}
#endif

pthread_spinlock_t lock;
static void *f (void *p)
{
  int a = 123456789;
  int *i = (int *) malloc (sizeof *i);
  *i = 987654321;
  int j;
  for (j = 0; j < 1; ++j)
    fprintf (stderr, "xxx %p %p %d\n", &a, i, getpid ());
  free (i);
  pthread_spin_unlock (&lock);
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
  pthread_spin_init (&lock, PTHREAD_PROCESS_PRIVATE);
  pthread_spin_lock (&lock);
  pthread_spin_trylock (&lock);
  char ok = pthread_create (&thread, NULL, f, NULL) == 0;
  free (malloc (1));
  fprintf (stderr, "yyy %d\n", ok);
#ifdef EXIT_GROUP
  syscall (231, 0);
#endif
  pthread_spin_lock (&lock);
  pthread_spin_destroy (&lock);

  if (ok) assert (pthread_join (thread, NULL) == 0);
  fprintf (stderr, "zzz\n");
#ifdef SIGNAL
  pthread_spin_init (&caught, PTHREAD_PROCESS_PRIVATE);
  pthread_spin_lock (&caught);
  fprintf (stderr, "%p\n", handler);
  signal (SIGINT, handler);
  pthread_spin_lock (&caught);
  pthread_spin_destroy (&caught);
  assert (signal (SIGINT, 0) == handler);
#endif
  return 0;
}
