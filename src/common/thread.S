/* vim: set ft=gas: */

#include <lib/util.h>
#include <lib/syscall-common.h>
#include <lib/syscall-offsets.h>

#include <common/thread.h>
#include <common/thread-local-offsets.h>

  .section .rodata

  .align 16
ERI_SYMBOL (th_text)
ERI_SYMBOL (th_text_enter)
  leaq	th_text - TE_SIZE(%rip), %rbx
  jmp	*th_text - TE_SIZE + TE__ENTER(%rip)

  .align 16
ERI_SYMBOL (th_text_leave)
  movq	th_text - TE_SIZE + TE__REGS_RBX(%rip), %rbx
  jmp	*th_text - TE_SIZE + TE__LEAVE(%rip)

ERI_SYMBOL (th_text_end)

  .text

ERI_FUNCTION (enter)

#define SAVE_REG(creg, reg) \
  movq	%reg, ERI_PASTE (TE__REGS_, creg)(%rbx);

  SAVE_REG (RSP, rsp)

  movq	TE__STACK(%rbx), %rsp
  pushfq
  popq	TE__REGS_RFLAGS(%rbx)
  pushq	$0
  popfq

  _ERI_FOREACH_GREG_NO_RBX_RSP (SAVE_REG)

  movq	TE__TH(%rbx), %rdi
  call	*TE__ENTRY(%rbx)
  ERI_ASSERT_FALSE

  ERI_END_FUNCTION (enter)

ERI_FUNCTION (eri_thread_entry__do_leave)

  movq	%rdi, %rbx

#define RESTORE_REG(creg, reg) \
  movq	ERI_PASTE (TE__REGS_, creg)(%rbx), %reg;

  _ERI_FOREACH_GREG_NO_RBX_RSP (RESTORE_REG)
  pushq	TE__REGS_RFLAGS(%rbx)
  popfq
  RESTORE_REG (RSP, rsp)

  jmp	*TE__TH_LEAVE(%rbx)

  ERI_END_FUNCTION (eri_thread_entry__do_leave)

ERI_FUNCTION (eri_thread_entry__syscall_interruptible)

  pushq	%rbx
  pushq	%rbp

  movq	%rdi, %rbx
  movq	%rsi, %rbp

  ERI_MOV_LM (.lsyscall_interrupt, TE__SYSCALL_INTERRUPT(%rbx), %rax)

  cmpl	$0, TE__SIG_PENDING(%rbx)
  je	.lsyscall
  movq	$ERI_EINTR, %rax
  jmp	.lsyscall_interrupt

.lsyscall:
  movq	ERI_SYS_SYSCALL_ARGS_NR(%rbp), %rax

  movq	ERI_SYS_SYSCALL_ARGS_A0(%rbp), %rdi
  movq	ERI_SYS_SYSCALL_ARGS_A1(%rbp), %rsi
  movq	ERI_SYS_SYSCALL_ARGS_A2(%rbp), %rdx
  movq	ERI_SYS_SYSCALL_ARGS_A3(%rbp), %r10
  movq	ERI_SYS_SYSCALL_ARGS_A4(%rbp), %r8
  movq	ERI_SYS_SYSCALL_ARGS_A5(%rbp), %r9
  syscall
.lsyscall_interrupt:
  movq	$0, TE__SYSCALL_INTERRUPT(%rbx)
  movq	%rax, ERI_SYS_SYSCALL_ARGS_RESULT(%rbp)
  popq	%rbp
  popq	%rbx
  ret

  ERI_END_FUNCTION (eri_thread_entry__syscall_interruptible)

ERI_FUNCTION (sig_return_back)

  movq	%rbx, ERI_SIGFRAME_CTX_MCTX_RBX(%rdi)
  movq	%rsp, ERI_SIGFRAME_CTX_MCTX_RSP(%rdi)
  movq	%rbp, ERI_SIGFRAME_CTX_MCTX_RBP(%rdi)
  movq	%r12, ERI_SIGFRAME_CTX_MCTX_R12(%rdi)
  movq	%r13, ERI_SIGFRAME_CTX_MCTX_R13(%rdi)
  movq	%r14, ERI_SIGFRAME_CTX_MCTX_R14(%rdi)
  movq	%r15, ERI_SIGFRAME_CTX_MCTX_R15(%rdi)
  movq	$0, ERI_SIGFRAME_CTX_MCTX_RFLAGS(%rdi)

  ERI_MOV_LM (.lsig_return_back, ERI_SIGFRAME_CTX_MCTX_RIP(%rdi), %rax)
  movq	%rdi, %rsp
.lsig_return_back:
  ret

  ERI_END_FUNCTION (sig_return_back)

ERI_FUNCTION (sig_op_ret)

  movq	%rdi, %rbx
  movq	TE__STACK(%rbx), %rsp

  movq	%rsi, %rdi
  call	sig_return_back

  movq	TE__TH(%rbx), %rdi
  call	*TE__SIG_ACTION(%rbx)
  ERI_ASSERT_FALSE

  ERI_END_FUNCTION (sig_op_ret)

ERI_FUNCTION (eri_thread_entry__test_access)
  movq	%rbx, TE__ACCESS_RBX(%rdi)
  ERI_LEA_MM (8(%rsp), TE__ACCESS_RSP(%rdi), %rax)
  movq	%rbp, TE__ACCESS_RBP(%rdi)
  movq	%r12, TE__ACCESS_R12(%rdi)
  movq	%r13, TE__ACCESS_R13(%rdi)
  movq	%r14, TE__ACCESS_R14(%rdi)
  movq	%r15, TE__ACCESS_R15(%rdi)
  ERI_MOV_MM ((%rsp), TE__ACCESS_RIP(%rdi), %rax)
  movb	$1, TE__TEST_ACCESS(%rdi)
  movb	$1, %al
  ret
  ERI_END_FUNCTION (eri_thread_entry__test_access)
