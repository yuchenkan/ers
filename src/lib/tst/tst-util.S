/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (tst_create_thread)

  movl	$__NR_clone, %eax

  movq	%rsi, %r10		/* ctid */

  movq	%rdi, %rsi		/* child_stack */
  movq	%rdx, -16(%rsi)
  movq	%rcx, -8(%rsi)

#define FLAGS \
  (ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SIGHAND	\
   | ERI_CLONE_THREAD | ERI_CLONE_SYSVSEM | ERI_CLONE_CHILD_CLEARTID)

  movq	$FLAGS, %rdi

  xorq	%rdx, %rdx
  xorq	%r8, %r8

  syscall
  testq	%rax, %rax
  jl	.lerror
  jz	.lchild

  ret

.lchild:
  movq	-16(%rsp), %rax
  movq	-8(%rsp), %rdi
  call	*%rax

  movl	$__NR_exit, %eax
  xorq	%rdi, %rdi
  syscall

.lerror:
  ERI_ASSERT_FALSE
  .size tst_create_thread, . - tst_create_thread
