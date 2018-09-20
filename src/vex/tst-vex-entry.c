#include <asm/unistd.h>

#include "vex-pub.h"
#include "recorder.h"
#include "common.h"

#include "lib/syscall.h"
#include "lib/util.h"
#include "lib/printf.h"

char __attribute__ ((aligned (16))) stack[8 * 1024 * 1024];

#define CHILD_STACK_SIZE (1024 * 1024)
char __attribute__ ((aligned (16))) child_stack[CHILD_STACK_SIZE];

/*
  movq	8(%rip), %rdi	\n\
  movq	%fs:0, %rax	\n\
  movq	%fs:0x100000000, %rax	\n\
  movq	%fs:(%rax), %rax	\n\

  call	1f		\n\
  ret	$16		\n\
  ret			\n\
  call	*8(%rax, %rbx, 4)		\n\
  jmp	*8(%rax, %rbx, 4)		\n\
  jmp	*%fs:8(%rax, %rbx, 4)		\n\
  jmp	*8(%rip)		\n\
  jmp	*%fs:8(%rip)		\n\
*/

#if 0

asm ("  .text		\n\
  .align 16		\n\
  .type tst, @function	\n\
tst:			\n\
  movq	%rdi, %rsi				\n\
  movq	$" _ERS_STR (ERI_ARCH_SET_FS) ", %rdi	\n\
  movl	$" _ERS_STR (__NR_arch_prctl) ", %eax	\n\
  syscall					\n\
  jmp	1f		\n\
  nop			\n\
1:			\n\
  movq	%fs:0, %rdi				\n\
  movl	$" _ERS_STR (__NR_exit) ", %eax		\n\
  syscall					\n\
  .size tst, .-tst	\n\
  .previous		\n"
);

#else

#define CLONE_FLAGS \
  (ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SIGHAND	\
   | ERI_CLONE_THREAD | ERI_CLONE_SYSVSEM | ERI_CLONE_SETTLS)

asm ("  .text		\n\
  .align 16		\n\
  .type tst, @function	\n\
tst:			\n\
  movq	%rdi, %r8							\n\
  movq	$" _ERS_STR (CLONE_FLAGS) ", %rdi				\n\
  leaq	child_stack + " _ERS_STR (CHILD_STACK_SIZE) "(%rip), %rsi	\n\
  xorq	%rdx, %rdx							\n\
  xorq	%r10, %r10							\n\
  movl	$" _ERS_STR (__NR_clone) ", %eax				\n\
  syscall								\n\
  testq	%rax, %rax	\n\
  jl	1f		\n\
  jz	2f		\n\
3:			\n\
  cmpq	$123, (%r8)	\n\
  jne	3b		\n\
  jmp	4f		\n\
1:			\n\
  movq	$0, %r15	\n\
  movq	$0, (%r15)	\n\
2:			\n\
  movq	$123, %fs:0	\n\
4:			\n\
  movq	$0, %rdi				\n\
  movl	$" _ERS_STR (__NR_exit) ", %eax		\n\
  syscall					\n\
  .size tst, .-tst	\n\
  .previous		\n"
);

#endif

void *tst (void *);

void __attribute__ ((visibility ("default")))
entry (void *rip, void *rsp, unsigned long fsbase)
{
  eri_dump_maps (ERI_STDOUT);

  unsigned long p = 0;

  size_t buf_size = 256 * 1024 * 1024;
  char *buf = (char *) ERI_ASSERT_SYSCALL_RES (
		mmap, 0, buf_size, ERI_PROT_READ | ERI_PROT_WRITE,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);

  struct eri_vex_context ctx = { 4096 };
  if (rip == 0)
    {
      ctx.comm.rip = (unsigned long) tst;
      ctx.comm.rdi = (unsigned long) &p;
      ctx.comm.rsp = (unsigned long) (stack + sizeof stack);
    }
  else
    {
      ctx.comm.rip = (unsigned long) rip;
      ctx.comm.rsp = (unsigned long) rsp;
      ctx.comm.fsbase = fsbase;
    }

  /* eri_printf ("%lx %lx %lx\n", p, &p, tst (&p)); */

  const char *path = "vex_data";
  if (ERI_SYSCALL_ERROR_P (ERI_SYSCALL (mkdir, path, ERI_S_IRWXU)))
    eri_assert (eri_fprintf (ERI_STDERR, "failed to create %s\n", path) == 0);
  eri_vex_enter (buf, buf_size, &ctx, path, 1);
  eri_assert (0);
}
