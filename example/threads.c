#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

static void* f(void *p)
{
  int a = 123456789;
  int* i = (int*)malloc(sizeof (int));
  *i = 987654321;
  fprintf(stderr, "xxx %p %p\n", &a, i);
  free(i);
  return NULL;
}

int main()
{
  pthread_t thread;
  assert(pthread_create(&thread, NULL, f, NULL) == 0);
  fprintf(stderr, "yyy\n");
  assert(pthread_join(thread, NULL) == 0);
  fprintf(stderr, "zzz\n");
  return 0;
}
