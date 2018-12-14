/* vim: set ft=gas: */

#include "rtld-offsets.h"

  .text

  .align 16
  ERI_GLOBAL_HIDDEN (eri_start)
  .type eri_start, @function
eri_start:
  subq	$16, %rsp
  jmp	eri_init
  .size start, . - start

  .align 16
  .type set_context, @function
set_context:
  movq	%rbx, ERI_INIT_CONTEXT_RBX(%rdi)
  movq	%rsp, ERI_INIT_CONTEXT_RSP(%rdi)
  movq	%rbp, ERI_INIT_CONTEXT_RBP(%rdi)
  movq	%r12, ERI_INIT_CONTEXT_R12(%rdi)
  movq	%r13, ERI_INIT_CONTEXT_R13(%rdi)
  movq	%r14, ERI_INIT_CONTEXT_R14(%rdi)
  movq	%r15, ERI_INIT_CONTEXT_R15(%rdi)
  movb	$ERI_LIVE, %al
  ret
  .size set_context, . - set_context

  .align 16
  ERI_GLOBAL_HIDDEN (eri_init_context)
  .type eri_init_context, @function
eri_init_context:

  pushq	%rdi
  pushq	%rsi
  pushq	%rdx

  movq	$ERI_MARK_INIT_STACK, %rsi
  call	eri_save_mark

  popq	%rdx
  popq	%rsi
  movq	(%rsp), %rdi
  subq	%rsi, %rdx
  call	eri_save_init_map_data

  subq	$ERI_INIT_CONTEXT_SIZE16, %rsp
  call	set_context
  cmpb	$ERI_LIVE, %al
  jne	.lreplay

  movq	ERI_INIT_CONTEXT_SIZE16(%rsp), %rdi
  movq	%rsp, %rsi
  call	eri_save_init_context

  addq	$ERI_INIT_CONTEXT_SIZE16, %rsp
  movq	(%rsp), %rdi
  call	eri_fclose
  testl	%eax, %eax
  jnz	.lerror
  addq	$8, %rsp
  movb	$ERI_LIVE, %al
  ret

.lreplay:
  movb	%al, %dl

  movl	$__NR_munmap, %eax
  movq	ERI_INIT_CONTEXT_UNMAP_START(%rsp), %rdi
  movq	ERI_INIT_CONTEXT_UNMAP_SIZE(%rsp), %rsi
  syscall
  testq	%rax, %rax
  jnz	.lerror

  movb	%dl, %al
  ret

.lerror:
  ERI_ASSERT_FALSE
  .size eri_init_context, . - eri_init_context
