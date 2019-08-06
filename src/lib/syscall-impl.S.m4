/* vim: set ft=gas: */
m4_include(`m4/util.m4')

#include <lib/util.h>
#include <m4_syscall_h>
#include <lib/syscall-offsets.h>

  .text

ERI_FUNCTION (clone)
  .cfi_startproc
  movl	$__NR_clone, %eax
  movq	%rcx, %r10
  m4_syscall(0)
  testq	%rax, %rax
  jz	.lclone_start_child
  ret
  .cfi_endproc
.lclone_start_child:
  popq	%rdx
  popq	%rsi
  popq	%rdi
  popq	%rax
  jmp	*%rax
  ERI_END_FUNCTION (clone)

ERI_FUNCTION (m4_ns(assert_sys_sigreturn))
  .cfi_startproc
  .cfi_def_cfa rsp, 0
  .cfi_offset r8, ERI_SIGFRAME_CTX_MCTX_R8
  .cfi_offset r9, ERI_SIGFRAME_CTX_MCTX_R9
  .cfi_offset r10, ERI_SIGFRAME_CTX_MCTX_R10
  .cfi_offset r11, ERI_SIGFRAME_CTX_MCTX_R11
  .cfi_offset r12, ERI_SIGFRAME_CTX_MCTX_R12
  .cfi_offset r13, ERI_SIGFRAME_CTX_MCTX_R13
  .cfi_offset r14, ERI_SIGFRAME_CTX_MCTX_R14
  .cfi_offset r15, ERI_SIGFRAME_CTX_MCTX_R15
  .cfi_offset rdi, ERI_SIGFRAME_CTX_MCTX_RDI
  .cfi_offset rsi, ERI_SIGFRAME_CTX_MCTX_RSI
  .cfi_offset rbp, ERI_SIGFRAME_CTX_MCTX_RBP
  .cfi_offset rbx, ERI_SIGFRAME_CTX_MCTX_RBX
  .cfi_offset rdx, ERI_SIGFRAME_CTX_MCTX_RDX
  .cfi_offset rax, ERI_SIGFRAME_CTX_MCTX_RAX
  .cfi_offset rcx, ERI_SIGFRAME_CTX_MCTX_RCX
  .cfi_offset rsp, ERI_SIGFRAME_CTX_MCTX_RSP
  .cfi_offset rip, ERI_SIGFRAME_CTX_MCTX_RIP
  movl	$__NR_rt_sigreturn, %eax
  m4_syscall(0)
  ERI_ASSERT_FALSE
  .cfi_endproc
  ERI_END_FUNCTION (m4_ns(assert_sys_sigreturn))

ERI_FUNCTION (m4_ns(assert_sys_thread_die))
  .cfi_startproc
  movl	$0, (%rdi)

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
  .cfi_endproc
  ERI_END_FUNCTION (m4_ns(assert_sys_thread_die))
