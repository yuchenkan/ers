#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>

static void *
loop (void *p)
{
  if ((long) p == 32) syscall (SYS_exit_group, 0);
  while (p) continue;
  return NULL;
}

int
main (void)
{
  pthread_t th[64];
  char grp = 1;
  int i;
  for (i = 0; i < sizeof th / sizeof th[0]; ++i)
    assert (pthread_create (th + i, NULL, loop, grp ? (void *) (long) (i + 1) : NULL) == 0);
  if (! grp)
    for (i = 0; i < sizeof th / sizeof th[0]; ++i)
      assert (pthread_join (th[i], NULL) == 0);
  return 0;
}
