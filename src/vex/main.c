#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <asm/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>

void entry (void *rip, void *rsp, unsigned long fsbase);

char __attribute__ ((aligned (16))) stack[8 * 1024 * 1024];

static void
tst (void)
{
  fprintf (stderr, "%s %d\n", "123", 123);
  free (malloc (4 * 1024 * 1024));
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
main (int argc)
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
