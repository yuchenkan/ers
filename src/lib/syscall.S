/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

  .text

ERI_FUNCTION (clone)
  movl	$__NR_clone, %eax
  movq	%rcx, %r10
  syscall
  testq	%rax, %rax
  jz	.lclone_start_child
  ret
.lclone_start_child:
  popq	%rdx
  popq	%rsi
  popq	%rdi
  popq	%rax
  jmp	*%rax
  ERI_END_FUNCTION (clone)

ERI_FUNCTION (eri_assert_sys_sigreturn)
  movl	$__NR_rt_sigreturn, %eax
  syscall
  ERI_ASSERT_FALSE
  ERI_END_FUNCTION (eri_assert_sys_sigreturn)
