/* vim: set ft=gas: */

#include "tst/tst-live-quit-common.h"

#include "rtld-offsets.h"
#include "live-entry-offsets.h"

#include "lib/tst/tst-util.h"

#include "lib/util.h"
#include "lib/syscall.h"

ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text)
ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text_end)

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (tst_main)
  subq	$8, %rsp
  movq	%rsp, %rdi
  call	tst_live_quit_init
  pushq	$0
  jmp	tst_live_quit_main
  .size tst_main, . - tst_main

ERI_GLOBAL_HIDDEN_FUNCTION (eri_live_entry_start)
  pushq	%rsi
  call	tst_live_quit_set_thread
  movb	$1, %dil
  call	tst_live_quit_block_signals
  popq	%rsi
  movq	ERI_RTLD_RSP(%rsi), %rsp
  ret
  .size eri_live_entry_start, . - eri_live_entry_start

ERI_GLOBAL_HIDDEN_FUNCTION (eri_live_entry_clone)

  cmpb	$1, tst_live_quit_allow_clone
  jne	.lerror

  cmpq	$__NR_clone, ERI_LIVE_ENTRY_SYSCALL_INFO_RAX(%rcx)
  jne	.lerror

  pushq	%rsi
  pushq	%rdx
  pushq	%rcx
  call	tst_live_quit_sig_pending
  testb	%al, %al
  jnz	.lsig_ret
  popq	%r9
  popq	%r8
  popq	%rcx

  movl	$__NR_clone, %eax
  movq	ERI_LIVE_ENTRY_CLONE_INFO_FLAGS(%r8), %rdi
  movq	ERI_LIVE_ENTRY_CLONE_INFO_CHILD_STACK(%r8), %rsi
  movq	ERI_LIVE_ENTRY_CLONE_INFO_PTID(%r8), %rdx
  movq	ERI_LIVE_ENTRY_CLONE_INFO_CTID(%r8), %r10
  movq	ERI_LIVE_ENTRY_CLONE_INFO_NEWTLS(%r8), %r8

  movq	%rcx, -8(%rsi)

  syscall
  testq	%rax, %rax
  jz	.lchild
  jl	.lerror

  movq	%rax, ERI_LIVE_ENTRY_SYSCALL_INFO_RAX(%r9)

  movb	$1, %al
  ret

.lsig_ret:
  addq	$24, %rsp
  movb	$0, %al
  ret

.lchild:
  subq	$16, %rsp
  movq	8(%rsp), %rdi
  call	tst_live_quit_set_thread
  addq	$8, %rsp
  popq	%rdi
  movq	ERI_LIVE_THREAD_ENTRY_THREAD(%rdi), %rdi
  call	eri_live_start_thread

  movb	$1, %dil
  call	tst_live_quit_block_signals

  movq	-TST_LIVE_QUIT_STACK_SIZE + 8(%rsp), %rdi
  pushq	$0
  jmp	*-TST_LIVE_QUIT_STACK_SIZE + 8(%rsp)

  .size eri_live_entry_clone, . - eri_live_entry_clone

  .align 16
TST_WEAK_GLOBAL_HIDDEN (eri_live_entry_do_syscall)
.lerror:
  ERI_ASSERT_FALSE
