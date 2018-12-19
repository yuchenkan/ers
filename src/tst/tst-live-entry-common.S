/* vim: set ft=gas: */

#include "lib/util.h"
#include "lib/syscall.h"

#include "tst/tst-live-entry-common-offsets.h"

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (tst_live_entry)
  pushq	%rbx
  pushq	%rbp
  pushq	%r12
  pushq	%r13
  pushq	%r14
  pushq	%r15

  movq	%rsp, %rax
  movq	TST_CONTEXT_RSP(%rdi), %rsp
  pushq	%rax

  leaq	.ltst_live_entry_ctf(%rip), %rax
  pushq	%rax

  movq	TST_CONTEXT_RAX(%rdi), %rax
  movq	TST_CONTEXT_RBX(%rdi), %rbx
  movq	TST_CONTEXT_RCX(%rdi), %rcx
  movq	TST_CONTEXT_RDX(%rdi), %rdx
  movq	TST_CONTEXT_RSI(%rdi), %rsi
  movq	TST_CONTEXT_RBP(%rdi), %rbp
  movq	TST_CONTEXT_R8(%rdi), %r8
  movq	TST_CONTEXT_R9(%rdi), %r9
  movq	TST_CONTEXT_R10(%rdi), %r10
  movq	TST_CONTEXT_R11(%rdi), %r11
  movq	TST_CONTEXT_R12(%rdi), %r12
  movq	TST_CONTEXT_R13(%rdi), %r13
  movq	TST_CONTEXT_R14(%rdi), %r14
  movq	TST_CONTEXT_R15(%rdi), %r15

  pushq	TST_CONTEXT_RIP(%rdi)
  pushq	TST_CONTEXT_RFLAGS(%rdi)
  movq	TST_CONTEXT_RDI(%rdi), %rdi
  popfq
  ret
.ltst_live_entry_ctf:
  pushfq
  andq	$~ERI_TRACE_FLAG_MASK, (%rsp)
  popfq

  popq	%rsp

  popq	%r15
  popq	%r14
  popq	%r13
  popq	%r12
  popq	%rbp
  popq	%rbx
  ret
  .size tst_live_entry, . - tst_live_entry

ERI_GLOBAL_HIDDEN_FUNCTION (tst_sig_step_int_trigger)
  subq	$8, %rsp
  pushq	%rsi
  pushq	%rdx
  call	tst_sig_step_int_check_trigger
  popq	%rdx
  popq	%rsi
  addq	$8, %rsp

  testl	%eax, %eax
  jz	.lno_trigger

  movl	%eax, %edi
  jmp	eri_live_entry_sigaction

.lno_trigger:
  ret
  .size tst_sig_step_int_trigger, . - tst_sig_step_int_trigger
