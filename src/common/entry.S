/* vim: set ft=gas: */

#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/syscall-common.h>
#include <lib/syscall-offsets.h>

#include <common/entry-local-offsets.h>

  .section .rodata

  .align 16
ERI_SYMBOL (th_text)
ERI_SYMBOL (th_text_enter)
  leaq	th_text - EN_SIZE(%rip), %rbx
  jmp	*th_text - EN_SIZE + EN__ENTER(%rip)

  .align 16
ERI_SYMBOL (th_text_leave)
  movq	th_text - EN_SIZE + EN__REGS_RBX(%rip), %rbx
  jmp	*th_text - EN_SIZE + EN__REGS_RIP(%rip)

ERI_SYMBOL (th_text_end)

  .text

ERI_FUNCTION (enter)

#define SAVE_REG(creg, reg) \
  movq	%reg, ERI_PASTE (EN__REGS_, creg)(%rbx);

  SAVE_REG (RSP, rsp)

  movq	EN__STACK(%rbx), %rsp
  pushfq
  popq	EN__REGS_RFLAGS(%rbx)
  pushq	$0
  popfq

  ERI_FOREACH_GPREG_NO_RBX_RSP (SAVE_REG)

  movq	%rbx, %rdi
  call	*EN__ENTRY(%rbx)
  ERI_ASSERT_FALSE

  ERI_END_FUNCTION (enter)

ERI_FUNCTION (leave)

  movq	%rdi, %rbx

#define RESTORE_REG(creg, reg) \
  movq	ERI_PASTE (EN__REGS_, creg)(%rbx), %reg;

  ERI_FOREACH_GPREG_NO_RBX_RSP (RESTORE_REG)
  pushq	EN__REGS_RFLAGS(%rbx)
  popfq
  RESTORE_REG (RSP, rsp)

  jmp	*EN__TH_LEAVE(%rbx)

  ERI_END_FUNCTION (leave)

ERI_FUNCTION (eri_entry__sys_syscall_interruptible)

  pushq	%rbx
  pushq	%rbp

  movq	%rdi, %rbx
  movq	%rsi, %rbp

  ERI_MOV_LM (.lsyscall_interrupt, EN__SYSCALL_INTERRUPT(%rbx), %rax)

  cmpl	$0, EN__SIG_PENDING(%rbx)
  je	.lsyscall
  movq	$ERI_EINTR, ERI_SYS_SYSCALL_ARGS_RESULT(%rbp)
  xorb	%al, %al
  jmp	.lsyscall_interrupt_return

.lsyscall:
  movl	ERI_SYS_SYSCALL_ARGS_NR(%rbp), %eax

  movq	ERI_SYS_SYSCALL_ARGS_A0(%rbp), %rdi
  movq	ERI_SYS_SYSCALL_ARGS_A1(%rbp), %rsi
  movq	ERI_SYS_SYSCALL_ARGS_A2(%rbp), %rdx
  movq	ERI_SYS_SYSCALL_ARGS_A3(%rbp), %r10
  movq	ERI_SYS_SYSCALL_ARGS_A4(%rbp), %r8
  movq	ERI_SYS_SYSCALL_ARGS_A5(%rbp), %r9
  syscall
.lsyscall_interrupt:
  movq	$0, EN__SYSCALL_INTERRUPT(%rbx)
  movq	%rax, ERI_SYS_SYSCALL_ARGS_RESULT(%rbp)
  movb	$1, %al
.lsyscall_interrupt_return:
  popq	%rbp
  popq	%rbx
  ret

  ERI_END_FUNCTION (eri_entry__sys_syscall_interruptible)

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

ERI_FUNCTION (_eri_entry__test_access)
  movq	%rsi, EN__ACCESS_MEM(%rdi)
  movq	%rdx, EN__ACCESS_DONE(%rdi)
  movq	%rbx, EN__ACCESS_RBX(%rdi)
  ERI_LEA_MM (8(%rsp), EN__ACCESS_RSP(%rdi), %rax)
  movq	%rbp, EN__ACCESS_RBP(%rdi)
  movq	%r12, EN__ACCESS_R12(%rdi)
  movq	%r13, EN__ACCESS_R13(%rdi)
  movq	%r14, EN__ACCESS_R14(%rdi)
  movq	%r15, EN__ACCESS_R15(%rdi)
  ERI_MOV_MM ((%rsp), EN__ACCESS_RIP(%rdi), %rax)
  movb	$1, EN__TEST_ACCESS(%rdi)
  movb	$1, %al
  ret
  ERI_END_FUNCTION (_eri_entry__test_access)
