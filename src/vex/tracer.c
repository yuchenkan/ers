#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/user.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/personality.h>

int
main (void)
{
  pid_t pid = fork ();
  if (pid == 0)
    {
      assert (personality (PER_LINUX | ADDR_NO_RANDOMIZE) >= 0);
      assert (ptrace (PTRACE_TRACEME, 0, NULL, NULL) >= 0);
#if 0
      const char *t = "./main";
      assert (execl (t, t, "raw", NULL) >= 0);
#else
      const char *t = "../src/replayer";
      assert (execl (t, t, NULL) >= 0);
#endif
    }
  else
    {
      int status;
      pid_t wpid;
      assert ((wpid = waitpid (-1, &status, __WALL)) >= 0);
      assert (ptrace (PTRACE_SETOPTIONS, wpid, NULL, PTRACE_O_TRACECLONE) >= 0);
      while (! WIFEXITED (status) || wpid != pid)
      {
	if (! WIFEXITED (status))
	{
	  struct user_regs_struct regs;
	  assert (ptrace (PTRACE_GETREGS, wpid, &regs, &regs) >= 0);

	  if (wpid == pid)
	    printf (">>>> 0x%016llx\n", regs.rip);

	  assert (ptrace (PTRACE_SINGLESTEP, wpid, NULL, NULL) >= 0);
	}
	assert ((wpid = waitpid (-1, &status, __WALL)) >= 0);
      }
    }
  return 0;
}
