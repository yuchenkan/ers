#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>

#if 1
# define EXIT_GROUP
#endif

static void* f (void *p)
{
  int a = 123456789;
  int* i = (int*) malloc (sizeof *i);
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
  pthread_t thread;
  assert (pthread_create (&thread, NULL, f, NULL) == 0);
  free (malloc (1));
  fprintf (stderr, "yyy\n");
#ifdef EXIT_GROUP
  syscall (231, 0);
#endif
  assert (pthread_join (thread, NULL) == 0);
  fprintf (stderr, "zzz\n");
  return 0;
}
