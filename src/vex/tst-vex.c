#include <asm/unistd.h>

#include "vex-pub.h"
#include "recorder.h"

#include "lib/syscall.h"
#include "lib/util.h"
#include "lib/printf.h"

char __attribute__ ((aligned (4096))) buf[64 * 1024 * 1024];
char __attribute__ ((aligned (16))) stack[8 * 1024 * 1024];

/*
  movq	%fs:0, %rax	\n\
  movq	%fs:0x100000000, %rax	\n\
  movq	%fs:(%rax), %rax	\n\

  call	1f		\n\
  ret	$16		\n\
  ret			\n\
  call	*8(%rax, %rbx, 4)		\n\
  jmp	*8(%rax, %rbx, 4)		\n\
  jmp	*%fs:8(%rax, %rbx, 4)		\n\
*/

asm ("  .text		\n\
  .align 16		\n\
  .type tst, @function	\n\
tst:			\n\
  .cfi_startproc	\n\
  movq	%rdi, %rsi	\n\
  movq	$" _ERS_STR (ERI_ARCH_SET_FS) ", %rdi	\n\
  movl	$" _ERS_STR (__NR_arch_prctl) ", %eax	\n\
  syscall		\n\
  jz	1f		\n\
  nop			\n\
1:			\n\
  movl	$" _ERS_STR (__NR_exit) ", %eax		\n\
  movq	%fs:0, %rdi	\n\
  syscall		\n\
  .cfi_endproc		\n\
  .size tst, .-tst	\n\
  .previous		\n"
);

void *tst (void *);

void __attribute__ ((visibility ("default")))
entry ()
{
  unsigned long p = 0x3039;

  struct eri_vex_context ctx = { 4096 };
  ctx.comm.rip = (unsigned long) tst;
  ctx.comm.rdi = (unsigned long) &p;
  ctx.comm.rsp = (unsigned long) (stack + sizeof stack);

  /* eri_printf ("%lx %lx %lx\n", p, &p, tst (&p)); */

  const char *path = "vex_data";
  if (ERI_SYSCALL_ERROR_P (ERI_SYSCALL (mkdir, path, ERI_S_IRWXU)))
    eri_assert (eri_fprintf (2, "failed to create %s\n", path) == 0);
  eri_vex_enter (buf, sizeof buf, &ctx, path);
  eri_assert (0);
}
