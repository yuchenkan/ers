/* vim: set ft=gas: */

#include "tst/tst-live-entry-clone.h"
#include "tst/tst-live-entry-common.h"

#include "public/impl.h"

#include "lib/util.h"
#include "lib/syscall.h"

#include "live-entry-offsets.h"

  .text

ERI_GLOBAL_HIDDEN_FUNCTION (tst_clone)
  pushfq
  cmpb	$1, tst_no_tf
  je	.lno_tf
  orq	$ERI_TRACE_FLAG_MASK, (%rsp)
.lno_tf:

  movl	$__NR_clone, %eax
  movq	$ERI_SUPPORTED_CLONE_FLAGS, %rdi
  leaq	tst_child_stack, %rsi
  addq	$TST_CHILD_STACK_SIZE, %rsi
  movq	tst_ptid, %rdx
  movq	tst_ctid, %r10
  movq	tst_newtls, %r8
  cmpb	$1, tst_raw
  je	.lraw
  popfq
  nop
ERI_GLOBAL_HIDDEN (tst_clone_enter)
  _ERS_SYSCALL
ERI_GLOBAL_HIDDEN (tst_clone_leave)
  nop
ERI_GLOBAL_HIDDEN (tst_clone_nop)
  jmp	.ldone
.lraw:
  popfq
  nop
ERI_GLOBAL_HIDDEN (tst_clone_raw_enter)
  syscall
ERI_GLOBAL_HIDDEN (tst_clone_raw_leave)
  nop
ERI_GLOBAL_HIDDEN (tst_clone_raw_nop)
.ldone:
  pushfq
  andq	$~ERI_TRACE_FLAG_MASK, (%rsp)
  popfq

  cmpb	$1, completed
  jne	.lret

  testq	%rax, %rax
  jz	.lchild
.lret:
  ret
.lchild:
  movq	%fs:0, %rdi
  cmpb	$1, tst_raw
  je	.lno_entry
  movq	%gs:ERI_LIVE_THREAD_ENTRY_THREAD, %rsi
.lno_entry:
  call	tst_child
  movl	$__NR_exit, %eax
  movq	$0, %rdi
  syscall
  .size tst_clone, . - tst_clone
