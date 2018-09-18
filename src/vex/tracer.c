#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/personality.h>
#include <sys/stat.h>

#include "common.h"
#include "lib/util.h"
#include "lib/rbtree.h"

struct thread
{
  pid_t pid;
  FILE *f;
  ERI_RBT_NODE_FIELDS (thread, struct thread)
};

struct threads
{
  ERI_RBT_TREE_FIELDS (thread, struct thread)
};

ERI_DEFINE_RBTREE (static, thread, struct threads, struct thread, pid_t, eri_less_than)

static struct thread *
add_thread (const char *path, struct threads *threads, pid_t pid)
{
  struct thread *th = malloc (sizeof *th);
  assert (th);
  th->pid = pid;
  int fd = eri_open_path (path, "tracer-", ERI_OPEN_WITHID, thread_rbt_get_size (threads));
  th->f = fdopen (fd, "w");
  assert (th->f);
  thread_rbt_insert (threads, th);
  printf ("add thread: %ld %lu\n", (long) pid, thread_rbt_get_size (threads));
  return th;
}

static void
del_thread (struct threads *threads, struct thread *th)
{
  pid_t pid = th->pid;
  assert (fclose (th->f) == 0);
  thread_rbt_remove (threads, th);
  free (th);
  printf ("del thread: %ld %lu\n", (long) pid, thread_rbt_get_size (threads));
}

int
main (int argc, const char *argv[])
{
  const char *path = "ers_data";
  if (mkdir (path, S_IRWXU) != 0) assert (errno == EEXIST);

  pid_t pid = fork ();
  if (pid == 0)
    {
      assert (personality (PER_LINUX | ADDR_NO_RANDOMIZE) >= 0);
      assert (ptrace (PTRACE_TRACEME, 0, NULL, NULL) >= 0);
      if (argc == 1)
	assert (execl ("./tracee", "./tracee", NULL) >= 0);
      else
	assert (execvp (argv[1], (void *) (argv + 1)) >= 0);
    }
  else
    {
      struct threads threads;
      ERI_RBT_INIT_TREE (thread, &threads);

      int status;
      pid_t wpid;
      assert ((wpid = waitpid (-1, &status, __WALL)) >= 0);
      assert (ptrace (PTRACE_SETOPTIONS, wpid, NULL, PTRACE_O_TRACECLONE) >= 0);

      add_thread (path, &threads, wpid);
      while (! WIFEXITED (status) || wpid != pid)
	{
	  struct thread *th = thread_rbt_get (&threads, &wpid, ERI_RBT_EQ);

	  if (WIFEXITED (status))
	    {
	      /* All the mess comes from exit_group.  */
	      if (th) del_thread (&threads, th);
	    }
	  else
	    {
	      if (WSTOPSIG (status) == SIGSTOP)
		th = add_thread (path, &threads, wpid);

	      struct user_regs_struct regs;
	      if (ptrace (PTRACE_GETREGS, wpid, &regs, &regs) != 0)
		assert (errno == ESRCH);
	      else
		{
		  fprintf (th->f, "0x%016llx\n", regs.rip);

		  if (ptrace (PTRACE_SINGLESTEP, wpid, NULL, NULL) != 0)
		    assert (errno == ESRCH);
		}
	    }
	  assert ((wpid = waitpid (-1, &status, __WALL)) >= 0);
	}

      struct thread *th, *nth;
      ERI_RBT_FOREACH_SAFE (thread, &threads, th, nth)
	{
	  if (th->pid != pid)
	    printf ("thread left: %ld\n", (long) th->pid);
	  del_thread (&threads, th);
	}
    }
  return 0;
}
