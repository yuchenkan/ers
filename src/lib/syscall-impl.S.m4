/* vim: set ft=gas: */
m4_include(`m4/util.m4')

#include <lib/util.h>

  .text

ERI_FUNCTION (clone)
  movl	$__NR_clone, %eax
  movq	%rcx, %r10
  m4_syscall(0)
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

ERI_FUNCTION (m4_ns(assert_sys_sigreturn))
  movl	$__NR_rt_sigreturn, %eax
  m4_syscall(0)
  ERI_ASSERT_FALSE
  ERI_END_FUNCTION (m4_ns(assert_sys_sigreturn))

ERI_FUNCTION (m4_ns(assert_sys_thread_die))
  movq	$0, (%rdi)

  movl	$__NR_futex, %eax
  movq	$ERI_FUTEX_WAKE, %rsi
  movq	$1, %rdx
  m4_syscall(0)
  cmpq	$-4096, %rax
  ja	.lerror
1:
  jmp	1b
.lerror:
  ERI_ASSERT_FALSE
  ERI_END_FUNCTION (m4_ns(assert_sys_thread_die))
