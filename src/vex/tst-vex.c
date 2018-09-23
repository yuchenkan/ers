#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <asm/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

void entry (void *rip, void *rsp, unsigned long fsbase);

char __attribute__ ((aligned (16))) stack[8 * 1024 * 1024];

static void
tst (void)
{
  void *p = malloc (4 * 1024 * 1024);
  fprintf (stderr, "%p %s %d\n", p, "123", 123);
  free (p);
  exit (0);
}

asm ("  .text		\n\
  .align 16		\n\
  .type raw, @function	\n\
raw:			\n\
  movq	%rdi, %rsp	\n\
  jmp	tst		\n\
  .size raw, .-raw	\n\
  .previous		\n"
);

void raw (void *stack);

int
main (int argc, const char *argv[])
{
  if (argc == 1)
    {
      unsigned long fsbase;
      assert (syscall (SYS_arch_prctl, ARCH_GET_FS, &fsbase) == 0);
      entry (tst, stack + sizeof stack, fsbase);
    }
  else raw (stack + sizeof stack);
  return 0;
}
