/* vim: set ft=gas: */

#include "public/comm.h"
#include "public/recorder-offsets.h"

#include "live.h"
#include "live-offsets.h"

#include "lib/syscall.h"
#include "lib/syscall-offsets.h"

#define SI_CODE			ERI_SIGINFO_CODE

#define UCTX_SS_SP		ERI_UCONTEXT_STACK_SP

#define UCTX_R8			ERI_UCONTEXT_MCTX_R8
#define UCTX_R9			ERI_UCONTEXT_MCTX_R9
#define UCTX_R10		ERI_UCONTEXT_MCTX_R10
#define UCTX_R11		ERI_UCONTEXT_MCTX_R11
#define UCTX_R12		ERI_UCONTEXT_MCTX_R12
#define UCTX_R13		ERI_UCONTEXT_MCTX_R13
#define UCTX_R14		ERI_UCONTEXT_MCTX_R14
#define UCTX_R15		ERI_UCONTEXT_MCTX_R15
#define UCTX_RDI		ERI_UCONTEXT_MCTX_RDI
#define UCTX_RSI		ERI_UCONTEXT_MCTX_RSI
#define UCTX_RBP		ERI_UCONTEXT_MCTX_RBP
#define UCTX_RBX		ERI_UCONTEXT_MCTX_RBX
#define UCTX_RDX		ERI_UCONTEXT_MCTX_RDX
#define UCTX_RAX		ERI_UCONTEXT_MCTX_RAX
#define UCTX_RCX		ERI_UCONTEXT_MCTX_RCX
#define UCTX_RSP		ERI_UCONTEXT_MCTX_RSP
#define UCTX_RIP		ERI_UCONTEXT_MCTX_RIP
#define UCTX_RFLAGS		ERI_UCONTEXT_MCTX_RFLAGS

#define PTH_MARK		_ERS_COMMON_THREAD_MARK
#define PTH_OP			_ERS_COMMON_THREAD_OP

#define PTH_START		_ERS_COMMON_THREAD_START
#define PTH_RET			_ERS_COMMON_THREAD_RET
#define PTH_CONT		_ERS_COMMON_THREAD_CONT

#define PTH_DIR			_ERS_COMMON_THREAD_DIR

#define PTH_RBX			_ERS_COMMON_THREAD_RBX
#define PTH_VAR0		_ERS_COMMON_THREAD_VAR0
#define PTH_VAR1		_ERS_COMMON_THREAD_VAR1

#define PTH_THREAD_ENTRY	_ERS_COMMON_THREAD_THREAD_ENTRY
#define TH_ENTRY		ERI_LIVE_THREAD_ENTRY

#define TH_TOP			ERI_LIVE_THREAD_TOP
#define TH_TOP_SAVED		ERI_LIVE_THREAD_TOP_SAVED
#define TH_RSP			ERI_LIVE_THREAD_RSP
#define TH_STACK_SIZE		ERI_LIVE_THREAD_STACK_SIZE
#define TH_RFLAGS_SAVED		ERI_LIVE_THREAD_RFLAGS_SAVED
#define TH_TRACE_FLAG		ERI_LIVE_THREAD_TRACE_FLAG

#define TH_THREAD_INTERNAL_CONT	ERI_LIVE_THREAD_THREAD_INTERNAL_CONT
#define TH_THREAD_EXTERNAL_CONT	ERI_LIVE_THREAD_THREAD_EXTERNAL_CONT
#define TH_THREAD_CONT_END	ERI_LIVE_THREAD_THREAD_CONT_END

#define TH_THREAD_RET		ERI_LIVE_THREAD_THREAD_RET
#define TH_THREAD_RET_END	ERI_LIVE_THREAD_THREAD_RET_END

#define TH_THREAD_RESUME	ERI_LIVE_THREAD_THREAD_RESUME
#define TH_RESUME		ERI_LIVE_THREAD_RESUME
#define TH_THREAD_RESUME_RET	ERI_LIVE_THREAD_THREAD_RESUME_RET
#define TH_RESUME_RET		ERI_LIVE_THREAD_RESUME_RET

#define TH_COMPLETE_START	ERI_LIVE_THREAD_COMPLETE_START

#define TH_FIX_RESTART		ERI_LIVE_THREAD_FIX_RESTART
#define TH_FIX_RESTART_RAX	ERI_LIVE_THREAD_FIX_RESTART_RAX
#define TH_FIX_RESTART_RBX	ERI_LIVE_THREAD_FIX_RESTART_RBX
#define TH_FIX_RESTART_RIP	ERI_LIVE_THREAD_FIX_RESTART_RIP
#define TH_FIX_RESTART_RFLAGS	ERI_LIVE_THREAD_FIX_RESTART_RFLAGS

#define TH_RESTART		ERI_LIVE_THREAD_RESTART
#define TH_RESTART_START	ERI_LIVE_THREAD_RESTART_START

#define TH_SYNC_REPEAT_TRACE	ERI_LIVE_THREAD_SYNC_REPEAT_TRACE

#define TH_SIG_RBX		ERI_LIVE_THREAD_SIG_RBX
#define TH_SIG_RDI		ERI_LIVE_THREAD_SIG_RDI
#define TH_SIG_RSI		ERI_LIVE_THREAD_SIG_RSI
#define TH_SIG_RDX		ERI_LIVE_THREAD_SIG_RDX
#define TH_SIG_RSP		ERI_LIVE_THREAD_SIG_RSP
#define TH_SIG_RBP		ERI_LIVE_THREAD_SIG_RBP
#define TH_SIG_R12		ERI_LIVE_THREAD_SIG_R12
#define TH_SIG_R13		ERI_LIVE_THREAD_SIG_R13
#define TH_SIG_R14		ERI_LIVE_THREAD_SIG_R14
#define TH_SIG_R15		ERI_LIVE_THREAD_SIG_R15

#define TH_SIZE16		ERI_LIVE_THREAD_SIZE16

#define PTH_TST_SKIP_CTF	ERI_LIVE_THREAD_TST_SKIP_CTF

#define LABEL(label)			_ERS_PASTE (.l, label)
#define LABEL_PREFIX(prefix, label)	LABEL (_ERS_PASTE (prefix, label))
#define LABEL_SUFFIX(label, suffix)	LABEL (_ERS_PASTE (label, suffix))
#define LABEL_COMPLETE_START(label)	LABEL_SUFFIX (label, _complete_start)
#define LABEL_RESTART_START(label)	LABEL_SUFFIX (label, _restart_start)

#define MARK_SEC_PART_BIT_OFFSET	4
#define MARK_SEC_PART_BIT		(1 << MARK_SEC_PART_BIT_OFFSET)

#define LOAD_OP_OP(th, dst) \
  movq	PTH_OP(th), dst;						\
  shrq	$_ERS_OP_FLAGS_BITS, dst

#define LOAD_OP_RFLAGS(th, dst) \
  movq	PTH_OP(th), dst;						\
  andq	$_ERS_OP_FLAGS_MASK, dst

/************************************************/
/* eri_live_thread_template			*/
/************************************************/

  .data

  .global eri_live_thread_text
  .hidden eri_live_thread_text
  .global eri_live_thread_text_resume
  .hidden eri_live_thread_text_resume
  .global eri_live_thread_text_entry
  .hidden eri_live_thread_text_entry
  .global eri_live_thread_text_resume_ret
  .hidden eri_live_thread_text_resume_ret
  .global eri_live_thread_text_internal_cont
  .hidden eri_live_thread_text_internal_cont
  .global eri_live_thread_text_external_cont
  .hidden eri_live_thread_text_external_cont
  .global eri_live_thread_text_cont_end
  .hidden eri_live_thread_text_cont_end
  .global eri_live_thread_text_ret
  .hidden eri_live_thread_text_ret
  .global eri_live_thread_text_ret_end
  .hidden eri_live_thread_text_ret_end
  .global eri_live_thread_text_end
  .hidden eri_live_thread_text_end

  .align 16
eri_live_thread_text:
#define RELA(off)	eri_live_thread_text - TH_SIZE16 + off

eri_live_thread_text_entry:
  leaq	RELA (0)(%rip), %rbx
  jmp	*RELA (TH_ENTRY)(%rip)

  .align 16
eri_live_thread_text_internal_cont:
  movq	RELA (PTH_RBX)(%rip), %rbx
  .align 16, 0x90
eri_live_thread_text_external_cont:
  movq	$0, RELA (PTH_DIR)(%rip)
  jmp	*RELA (PTH_CONT)(%rip)
eri_live_thread_text_cont_end:

  .align 16
eri_live_thread_text_ret:
  movq	RELA (PTH_RBX)(%rip), %rbx
  jmp	*RELA (PTH_RET)(%rip)
eri_live_thread_text_ret_end:

  .align 16
eri_live_thread_text_resume:
  movq	UCTX_RBX(%rdx), %rbx
  movq	UCTX_RDX(%rdx), %rdx
  jmp	*RELA (TH_RESUME)(%rip)
  .align 16
eri_live_thread_text_resume_ret:
  movq	%rbx, RELA (PTH_RBX)(%rip)
  leaq	RELA (0)(%rip), %rbx
  jmp	*RELA (TH_RESUME_RET)(%rip)

  .align 16
eri_live_thread_text_end:

  .text

/************************************************/
/* eri_live_sigaction				*/
/************************************************/

  .align 16
  .type eri_live_sigaction, @function
  .global eri_live_sigaction
  .hidden eri_live_sigaction
eri_live_sigaction:

  movq	UCTX_SS_SP(%rdx), %rax
  movq	(%rax), %rax
  movq	%rbx, TH_SIG_RBX(%rax)
  /* %rbx is &live_thread.  */
  movq	%rax, %rbx

  /* %rax is the interrupted rip.  */
  movq	UCTX_RIP(%rdx), %rax

  /* Check nested signal.  */
  cmpq	.lnested_signal_start(%rip), %rax
  jb	.lnone_nested_signal
  cmpq	.lnested_signal_end(%rip), %rax
  jae	.lnone_nested_signal

  /* Nested signal, complete the context for the old signal
     and invoke.
  */
  movq	TH_SIG_RBX(%rbx), %rax
  movq	%rax, UCTX_RBX(%rdx)
  movq	TH_SIG_RDI(%rbx), %rax
  movq	%rax, UCTX_RDI(%rdx)
  movq	TH_SIG_RSI(%rbx), %rax
  movq	%rax, UCTX_RSI(%rdx)
  movq	TH_SIG_RDX(%rbx), %rax
  movq	%rax, UCTX_RDX(%rdx)
  leaq	sig_act(%rip), %rax /* TODO */
  movq	%rax, UCTX_RIP(%rdx)
  jmp	.linvoke

.lnone_nested_signal:
  movq	PTH_MARK(%rbx), %r11
  testq	%r11, %r11
  jz	.lzero_mark

  bt	$MARK_SEC_PART_BIT_OFFSET, %r11
  /* ! (mark & MARK_SEC_PART_BIT) means we need to restart.  */
  jnc	.lcheck_restart

  /* Otherwise means we may restart or complete.  */

  cmpq	TH_ENTRY(%rbx), %rax
  /* Complete if not inside eri_live_entry.  */
  jb	.lcomplete

  cmpq	TH_COMPLETE_START(%rbx), %rax
  /* Restart if the instruction not reached.  */
  jb	.lcheck_restart

  /* Complete if reached.  */
.lcomplete:
  /* Complete internally, we don't return to the user code.  */
  cmpq	$(MARK_SEC_PART_BIT | _ERS_MARK_INTERNAL_RET), %r11
  je	.linternal_complete
  /* Complete externally.  */
  movq	TH_THREAD_RESUME_RET(%rbx), %rax
  jmp	.lcomplete_resume
.linternal_complete:
  movq	TH_RESUME_RET(%rbx), %rax
.lcomplete_resume:
  movq	%rax, PTH_DIR(%rbx)
  jmp	.lresume

  /* 1. we are in user code.
     2. we need to fix restart sync_async.
     3. we need to fix context.
  */
.lzero_mark:
  leaq	.lsync_async(%rip), %r11
  cmpq	%r11, %rax
  /* Continue check if we are not in lsync_async to
     LABEL_RESTART_START (sync_async).
  */
  jb	.lcheck_ret_from_sync_async
  leaq	LABEL_RESTART_START (sync_async)(%rip), %r11
  cmpq	%r11, %rax
  /* Restart if we are in lsync_async to LABEL_RESTART_START (sync_async).  */
  jb	.lcheck_restart_fix_sync_async
  
  /* Continue check if we are returning from sync_async, eri_live_thread_ret
     is only called by sync_async when mark is zero.
  */
.lcheck_ret_from_sync_async:
  cmpq	TH_THREAD_RET(%rbx), %rax
  /* Continue check if we are about to run the sync_async instruction when we
     are not inside eri_live_thread_ret.
  */
  jb	.lcheck_sync_async_inst
  cmpq	TH_THREAD_RET_END(%rbx), %rax
  /* Restart if we are inside eri_live_thread_ret.  */
  jb	.lcheck_restart_fix_sync_async

.lcheck_sync_async_inst:
  LOAD_OP_OP (%rbx, %r11)
  cmpq	$_ERS_OP_SYNC_ASYNC, %r11
  /* Check if we are inside continue when op is not sync_async.  */
  jne	.lcheck_continue
  cmpq	PTH_RET(%rbx), %rax
  /* Restart if op is sync_async and we are at the sync_async
     instruction.
  */
  je	.lcheck_restart_fix_sync_async_inst

  /* Invoke user sigaction without further check. when op is sync_async
     it can't be inside eri_live_thread_*_cont and dir also must be zero.
  */
  jmp	.linvoke

.lcheck_continue:
  cmpq	TH_THREAD_INTERNAL_CONT(%rbx), %rax
  /* Check remaining code from mark zero to continue
     if we are not in eri_live_thread_*_cont.
  */
  jb	.lcheck_remaining
  /* Fix context internally if we are at eri_live_thread_internal_cont.  */
  je	.linternal_fix
  cmpq	TH_THREAD_CONT_END(%rbx), %rax
  /* Fix context externally if we are in eri_live_thread_external_cont.  */
  jb	.lfix

  /* Check remainging code from mark zero to continue by checking dir
     field.
  */
.lcheck_remaining:
  movq	PTH_DIR(%rbx), %r11
  testq	%r11, %r11
  /* Invoke sigaction if continue address is zero.  */
  jz	.linvoke
  cmpq	TH_THREAD_INTERNAL_CONT(%rbx), %r11
  /* Fix internally if continue address is eri_live_thread_internal_cont.  */
  je	.linternal_fix
  cmpq	TH_THREAD_EXTERNAL_CONT(%rbx), %r11
  /* Fix externally if continue address is eri_live_thread_external_cont.  */
  jmp	.lfix

/* Check sigtrap from single step tracing.  */
#define CHECK_TRACE(label) \
  cmpq	$ERI_SIGTRAP, %rdi;						\
  jne	label;								\
  cmpl	$ERI_TRAP_TRACE, SI_CODE(%rsi);					\
  jne	label

/* Ignore sigtrap from single step tracing.  */
#define IGNORE_TRACE(label) \
  CHECK_TRACE (label);							\
  ret

.lcheck_restart_fix_sync_async:
  IGNORE_TRACE (.lfix_restart)

.lcheck_restart_fix_sync_async_inst:
  CHECK_TRACE (.lfix_restart)
  cmpq	$0, TH_SYNC_REPEAT_TRACE(%rbx)
  jne	.lfix_restart
  movq	$1, TH_SYNC_REPEAT_TRACE(%rbx)
  ret

.lcheck_restart:
  IGNORE_TRACE (.lrestart)

  /* We are done all the branching.  */

.lrestart:
  bt	$MARK_SEC_PART_BIT_OFFSET, %r11
  /* We are in the second part while the instrcution is not reached.
     We still restart the instruction but we need to manully fix the
     context to let the interrupted code know where they are before
     we resume those code.
  */
  jc	.lfix_restart

  /* We are in the safe place, just mark and let the interrupted code
     do the restart.
  */
  movq	$1, TH_RESTART(%rbx)
  jmp	.lresume

.lfix_restart:
  movq	$1, TH_FIX_RESTART(%rbx)
  movq	UCTX_RBX(%rdx), %r11
  movq	%r11, TH_FIX_RESTART_RBX(%rbx)
  movq	%rbx, UCTX_RBX(%rdx)
  movq	%rax, TH_FIX_RESTART_RIP(%rbx)
  movq	UCTX_RFLAGS(%rdx), %r11
  andq	$~ERI_TRACE_FLAG_MASK, %r11
  movq	%r11, TH_FIX_RESTART_RFLAGS(%rbx)

  /* Resume to the restarter.  */
  movq	TH_RESTART_START(%rbx), %rax
  movq	%rax, UCTX_RIP(%rdx)

  /* Save the current context and return to the (possibly fixed) 
     interrupted context.
  */
.lresume:
  movq	%rdi, TH_SIG_RDI(%rbx)
  movq	%rsi, TH_SIG_RSI(%rbx)
  movq	%rdx, TH_SIG_RDX(%rbx)
  movq	%rsp, TH_SIG_RSP(%rbx)

  movq	%rbp, TH_SIG_RBP(%rbx)
  movq	%r12, TH_SIG_R12(%rbx)
  movq	%r13, TH_SIG_R13(%rbx)
  movq	%r14, TH_SIG_R14(%rbx)
  movq	%r15, TH_SIG_R15(%rbx)

  movq	UCTX_RIP(%rdx), %rax
  movq	%rax, TH_RESUME(%rbx)

  /* We are try to reset the trace flag saved on the stack so tracing won't
     be restored by popfq to avoid recursive sigtrap.
  */
  movq	$0, TH_TRACE_FLAG(%rbx)

  cmpq	$1, TH_RFLAGS_SAVED(%rbx)
  je	.lresume_check_reset_trace_flag

  movq	TH_TOP(%rbx), %rax
  cmpq	%rax, UCTX_RSP(%rdx)
  jae	.lresume_done_proc_saved_flags
  movq	TH_TOP(%rbx), %rax
  subq	TH_STACK_SIZE(%rbx), %rax
  cmpq	%rax, UCTX_RSP(%rdx)
  jbe	.lresume_done_proc_saved_flags

.lresume_check_reset_trace_flag:
  movq	TH_TOP(%rbx), %rax

  movq	-8(%rax), %r11
  andq	$ERI_TRACE_FLAG_MASK, %r11
  movq	%r11, TH_TRACE_FLAG(%rbx)
  andq	$~ERI_TRACE_FLAG_MASK, -8(%rax)

.lresume_done_proc_saved_flags:

  movq	UCTX_RBP(%rdx), %rbp
  movq	UCTX_R8(%rdx), %r8
  movq	UCTX_R9(%rdx), %r9
  movq	UCTX_R12(%rdx), %r12
  movq	UCTX_R13(%rdx), %r13
  movq	UCTX_R14(%rdx), %r14
  movq	UCTX_R15(%rdx), %r15

  /* Clear the trace flag.  */
  pushq	UCTX_RFLAGS(%rdx)
  andq	$~ERI_TRACE_FLAG_MASK, (%rsp)
  popfq

  movq	UCTX_RSP(%rdx), %rsp
  movq	UCTX_RAX(%rdx), %rax
  movq	UCTX_RCX(%rdx), %rcx
  movq	UCTX_RDI(%rdx), %rdi
  movq	UCTX_RSI(%rdx), %rsi
  movq	UCTX_R10(%rdx), %r10
  movq	UCTX_R11(%rdx), %r11

  jmp	*TH_THREAD_RESUME(%rbx)

  /* %rbx is &live_thread, the interrupted %rbx is saved in RBX.
     %rip is saved in CNT. %rflags is the interrupted %rflags & ~tf,
     All other regs are not modified.
  */
  .global eri_live_resume_ret
  .hidden eri_live_resume_ret
eri_live_resume_ret:
  /* Modify the context based on the new register values.  */
  xchgq	%rsp, TH_RSP(%rbx)
  pushq	%rdx
  movq	TH_SIG_RDX(%rbx), %rdx
  movq	%rax, UCTX_RAX(%rdx)
  movq	PTH_RBX(%rbx), %rax
  movq	%rax, UCTX_RBX(%rdx)
  movq	%rcx, UCTX_RCX(%rdx)
  popq	%rax
  movq	%rax, UCTX_RDX(%rdx)
  movq	%rsi, UCTX_RSI(%rdx)
  movq	%rdi, UCTX_RDI(%rdx)
  movq	TH_RSP(%rbx), %rax
  movq	%rax, UCTX_RSP(%rdx)
  movq	%rbp, UCTX_RBP(%rdx)
  movq	%r8, UCTX_R8(%rdx)
  movq	%r9, UCTX_R9(%rdx)
  movq	%r10, UCTX_R10(%rdx)
  movq	%r11, UCTX_R11(%rdx)
  movq	%r12, UCTX_R12(%rdx)
  movq	%r13, UCTX_R13(%rdx)
  movq	%r14, UCTX_R14(%rdx)
  movq	%r15, UCTX_R15(%rdx)

  /* Set the trace flag in context if it's set originally.
     The internal code won't set the trace flag, so if either the
     tf is set in the saved %rflags or the interrupted %rflags,
     we set it back.
  */
  movq	UCTX_RFLAGS(%rdx), %rax
  pushfq
  popq	UCTX_RFLAGS(%rdx)
  /* Set if it's set in the interrupted %rflags.  */
  andq	$ERI_TRACE_FLAG_MASK, %rax
  /* Set if it's set in the saved %rflags.  */
  orq	TH_TRACE_FLAG(%rbx), %rax
  orq	%rax, UCTX_RFLAGS(%rdx)
  /* Set trace flag in r11 accordingly if op is syscall and
     we are completing the instruction.
  */
  cmpq	$_ERS_OP_SYSCALL, PTH_OP(%rbx)
  jne	.ldone_restore_trace_flag
  cmpq	$0, PTH_DIR(%rbx)
  je	.ldone_restore_trace_flag
  orq	%rax, UCTX_R11(%rdx)
.ldone_restore_trace_flag:

  movq	PTH_CONT(%rbx), %rax
  movq	%rax, UCTX_RIP(%rdx)

  /* Set rsp to top again.  */
  movq	%rsp, TH_RSP(%rbx)
  movq	$0, TH_FIX_RESTART(%rbx)

  movq	TH_SIG_RBP(%rbx), %rbp
  movq	TH_SIG_R12(%rbx), %r12
  movq	TH_SIG_R13(%rbx), %r13
  movq	TH_SIG_R14(%rbx), %r14
  movq	TH_SIG_R15(%rbx), %r15

  /* %rdi is not used in do_invoke
     movq	TH_SIG_RDI(%rbx), %rdi
  */
  movq	TH_SIG_RSI(%rbx), %rsi
  movq	TH_SIG_RSP(%rbx), %rsp
  /* Clear INTR, see .latomic_xchg_complete_start.  */
  movq	$0, PTH_DIR(%rbx)
  jmp	.ldo_invoke

.linternal_fix:
  /* The only difference between internal and external is %rbx
     is restored if we run externally to make modifing %rbx is
     visible, internally we keep %rbx &live_thread to make jumps
     possible.
  */
  movq	PTH_RBX(%rbx), %rax
  movq	%rax, UCTX_RBX(%rdx)

.lfix:
  /* Clear INTR, see .latomic_xchg_complete_start.  */
  movq	$0, PTH_DIR(%rbx)

  movq	PTH_CONT(%rbx), %rax
  movq	%rax, UCTX_RIP(%rdx)

.linvoke:
  movq	%rdi, TH_SIG_RDI(%rbx)

.ldo_invoke:
  /* TODO fix ctx->stack */
  movq	UCTX_SS_SP(%rdx), %rdi
  movq	%rsp, %rcx
  subq	$24, %rsp
  call	eri_live_copy_stack
  popq	%rsi
  popq	%rdx
  movq	%rax, %rsp

  movq	%rsi, TH_SIG_RSI(%rbx)
  movq	%rdx, TH_SIG_RDX(%rbx)

  movl	$__NR_rt_sigprocmask, %eax
  movq	$ERI_SIG_SETMASK, %rdi
  leaq	eri_live_sigempty, %rsi
  movq	$0, %rdx
  movq	$ERI_SIG_SETSIZE, %r10
  syscall
.lnested_signal_start:
  testq	%rax, %rax
  jnz	.lerror
  movq	TH_SIG_RDI(%rbx), %rdi
  movq	TH_SIG_RSI(%rbx), %rsi
  movq	TH_SIG_RDX(%rbx), %rdx
  movq	TH_SIG_RBX(%rbx), %rbx
  movq	sig_act, %rax	/* TODO */
  jmp	*%rax
.lnested_signal_end:

.lerror:
  movq	$0, %r15
  movq	$0, (%r15)
  .size eri_live_sigaction, . - eri_live_sigaction

/************************************************/
/* eri_live_entry				*/
/************************************************/

  .align 16
  .type eri_live_entry, @function
  .global eri_live_entry
  .hidden eri_live_entry
eri_live_entry:
  xchgq	%rsp, TH_RSP(%rbx)

  /* top ---
	 rflags
	 rax/rdi/rsi/rdx/rcx/r8/r9/r10/r11
     rsp ---
	 rflags w/o tf
  */

  pushfq

  pushfq
#ifndef ERI_NON_TST
  /* We need to keep tf for same test.  */
  cmpq	$1, PTH_TST_SKIP_CTF(%rbx)
  je	.ltst_skip_ctf
#endif
  andq	$~ERI_TRACE_FLAG_MASK, (%rsp)
  popfq
  subq	$8, %rsp
#ifndef ERI_NON_TST
.ltst_skip_ctf:
#endif

  popq	-ERI_LIVE_ENTRY_SAVED_REG_SIZE(%rsp) /* STACK_RFLAGS_CTF */

  movq	$1, TH_RFLAGS_SAVED(%rbx)

  pushq	%rax
  pushq	%rdi
  pushq	%rsi
  pushq	%rdx
  pushq	%rcx
  pushq	%r8
  pushq	%r9
  pushq	%r10
  pushq	%r11	/* top - ERI_LIVE_ENTRY_SAVED_REG_SIZE */

#define STACK_RFLAGS		72
#define STACK_RAX		64
#define STACK_RDI		56
#define STACK_RSI		48
#define STACK_RDX		40
#define STACK_RCX		32
#define STACK_R8		24
#define STACK_R9		16
#define STACK_R10		8
#define STACK_R11		0

#define RESTORE_GENERAL_REGS \
  popq	%r11;								\
  popq	%r10;								\
  popq	%r9;								\
  popq	%r8;								\
  popq	%rcx;								\
  popq	%rdx;								\
  popq	%rsi;								\
  popq	%rdi;								\
  popq	%rax

#define RESTORE_RFLAGS \
  movq	$0, TH_RFLAGS_SAVED(%rbx);					\
  popfq

#define RESTORE_EXTERNAL_RET \
  RESTORE_GENERAL_REGS;							\
  RESTORE_RFLAGS;							\
  xchgq	TH_RSP(%rbx), %rsp

#define RESTORE_INTERNAL_RET \
  RESTORE_EXTERNAL_RET;							\
  movq	$0, PTH_MARK(%rbx)

#define STACK_RFLAGS_CTF	-8

  LOAD_OP_OP (%rbx, %r11)

  cmpq	$_ERS_OP_SYSCALL, %r11
  je	.lsyscall
  cmpq	$_ERS_OP_SYNC_ASYNC, %r11
  je	.lsync_async

#define LABEL_ATOMIC(label)	LABEL_PREFIX (atomic_, label)

/* %r11 is op.  */
#define IF_ATOMIC(op, label) \
  cmpq	$_ERS_PASTE (_ERS_OP_ATOMIC_, op), %r11;			\
  je	LABEL_ATOMIC (label)

  IF_ATOMIC (LOAD, load)
  IF_ATOMIC (STOR, stor)
  IF_ATOMIC (INC, inc)
  IF_ATOMIC (DEC, dec)
  IF_ATOMIC (XCHG, xchg)
  IF_ATOMIC (CMPXCHG, cmpxchg)

  jmp	.lerror

#define SET_LABEL_FIELD(label, fld, reg) \
  leaq	label(%rip), reg;						\
  movq	reg, fld(%rbx)
  
#define SET_COMPLETE_START(label, reg) \
  SET_LABEL_FIELD (LABEL_COMPLETE_START (label), TH_COMPLETE_START, reg)

#define SET_RESTART_START(label, reg) \
  SET_LABEL_FIELD (LABEL_RESTART_START (label), TH_RESTART_START, reg)

#define SET_COMPLETE_RESTART_START(label, reg) \
  SET_COMPLETE_START (label, reg);					\
  SET_RESTART_START (label, reg)

#define CHECK_RESTART(label) \
  cmpq	$1, TH_RESTART(%rbx);						\
  je	LABEL_RESTART_START (label)

#define MARK_SEC_PART_AND_CHECK_RESTART(label) \
  orq	$MARK_SEC_PART_BIT, PTH_MARK(%rbx);				\
  CHECK_RESTART (label)

#define TST_MARK_COMPLETE_START(label) \
  .global ERI_TST_LIVE_COMPLETE_START_NAME (label);			\
  .hidden ERI_TST_LIVE_COMPLETE_START_NAME (label);			\
ERI_TST_LIVE_COMPLETE_START_NAME (label):

/* If not TST, it's not required as tf is already cleared in new_rflags,
   so when tst_skip_ctf is 0.
*/
#ifndef ERI_NON_TST
# define TST_NEW_RFLAGS_CTF(reg_or_mem) \
  cmpq	$0, PTH_TST_SKIP_CTF(%rbx);					\
  je	1f;								\
  andq	$~ERI_TRACE_FLAG_MASK, reg_or_mem;				\
1:
#else
# define TST_NEW_RFLAGS_CTF(reg_or_mem)
#endif

/* %rsp is top - ERI_LIVE_ENTRY_SAVED_REG_SIZE.  */
#define SAVE_NEW_RFLAGS(reg) \
  pushfq;								\
  popq	reg;								\
									\
  /* Reset tf:							*/	\
									\
  /* rflags = (rflags & TF_MASK) | new_rflags			*/	\
									\
  /* Setting rflags has to be like this. We can't move rflags	*/	\
  /* out of stack as by so clear tf code in lresume may not	*/	\
  /* work.  */								\
  andq	$ERI_TRACE_FLAG_MASK, STACK_RFLAGS(%rsp);			\
  TST_NEW_RFLAGS_CTF (reg)						\
  orq	reg, STACK_RFLAGS(%rsp)

/* Destory %rax.
   We have to atomically set dir to cnt if no signal yet, because signal
   can happen between any two instructions, so we have to keep dir
   zero when we leave this place. There are three possible ways leaving
   here: 1, no signal, dir is cleared in cont, 2, signal before setting
   mark to 0, dir is cleared in resume_ret, 3, signal after, dir is cleared
   in fix.
*/
#define CHECK_SET_DIR(cont, reg) \
  xorq	%rax, %rax;							\
  movq	_ERS_PASTE (TH_THREAD_, _ERS_PASTE (cont, _CONT))(%rbx), reg;	\
  cmpxchgq	reg, PTH_DIR(%rbx)

#define EXTERNAL_RET_DIR(reg) \
  CHECK_SET_DIR (EXTERNAL, reg);					\
									\
  RESTORE_EXTERNAL_RET;							\
  jmp	*TH_THREAD_RET(%rbx)

#define INTERNAL_RET_DIR(reg) \
  CHECK_SET_DIR (INTERNAL, reg);					\
									\
  RESTORE_INTERNAL_RET;							\
  jmp	*PTH_DIR(%rbx)

#define ENTER_RESTART(reg) \
  movq	PTH_START(%rbx), reg;						\
  movq	reg, PTH_CONT(%rbx);						\
  movq	$0, TH_RESTART(%rbx)

#define RESTART_RESUME_RET \
  ENTER_RESTART (%rax);							\
									\
  RESTORE_INTERNAL_RET;							\
  jmp	*TH_RESUME_RET(%rbx)

#define CALL_TH(th_reg, fn) \
  movq	%rbx, th_reg;							\
  call	fn

/************************************************/
/* eri_live_entry: syscall			*/
/************************************************/

.lsyscall:
  SET_COMPLETE_RESTART_START (syscall, %r11)

  /* For rflags w/o tf.  */
  subq	$8, %rsp

  MARK_SEC_PART_AND_CHECK_RESTART (syscall)

  popfq
  movq	TH_RSP(%rbx), %rsp
  syscall
LABEL_COMPLETE_START (syscall):
  TST_MARK_COMPLETE_START (syscall)

  movq	TH_TOP_SAVED(%rbx), %rsp
  movq	%r11, STACK_R11(%rsp)
  movq	%rax, STACK_RAX(%rsp)

  SAVE_NEW_RFLAGS (%rax)

  /* Reset tf for %r11: r11 = (rflags & TF_MASK) | r11  */
  movq	STACK_RFLAGS(%rsp), %rax
  andq	$ERI_TRACE_FLAG_MASK, %rax
  TST_NEW_RFLAGS_CTF (STACK_R11(%rsp))
  orq	%rax, STACK_R11(%rsp)

  movq	PTH_START(%rbx), %rax
  movq	%rax, STACK_RCX(%rsp)

  INTERNAL_RET_DIR (%r11)

LABEL_RESTART_START (syscall):
  movq	TH_TOP_SAVED(%rbx), %rsp

  RESTART_RESUME_RET

/************************************************/
/* eri_live_entry: sync_async			*/
/************************************************/

.lsync_async:
  SET_RESTART_START (sync_async, %rax)
  movq	$0, TH_SYNC_REPEAT_TRACE(%rbx)

  movq	%rcx, %rdi
  CALL_TH (%rsi, eri_live_sync_async)

  RESTORE_GENERAL_REGS

  movq	$0, PTH_MARK(%rbx)
  /* Check restart modifies rflags.  */
  CHECK_RESTART (sync_async)

  RESTORE_RFLAGS
.lsync_async1:
  xchgq	TH_RSP(%rbx), %rsp
.lsync_async2:
  jmp	*TH_THREAD_RET(%rbx)

LABEL_RESTART_START (sync_async):
  /* TODO check rcx for rep.  */

  /* Not fixing if %rdi is not set to the interrupted rip.  */
  cmpq	$0, TH_FIX_RESTART(%rbx)
  je	.lsync_async_restart_restore

  movq	%rax, TH_FIX_RESTART_RAX(%rbx)

  movq	PTH_RET(%rbx), %rax
  cmpq	%rax, TH_FIX_RESTART_RIP(%rbx)
  je	.lsync_async_restart_restore_inst

#define SYNC_JMP_IF_BELOW(label, dst) \
  leaq	label(%rip), %rax;						\
  cmpq	%rax, TH_FIX_RESTART_RIP(%rbx);					\
  jb	dst

  SYNC_JMP_IF_BELOW (.lsync_async1, .lsync_async_restart_restore1)
  SYNC_JMP_IF_BELOW (.lsync_async2, .lsync_async_restart_restore2)
  jmp	.lsync_async_restart_restore3

.lsync_async_restart_restore_inst:
  movq	TH_FIX_RESTART_RBX(%rbx), %rax
  movq	%rax, PTH_RBX(%rbx)
.lsync_async_restart_restore3:
  xchgq	%rsp, TH_RSP(%rbx)
.lsync_async_restart_restore2:
  pushq	TH_FIX_RESTART_RFLAGS(%rbx)
.lsync_async_restart_restore1:
  movq	TH_FIX_RESTART_RAX(%rbx), %rax
.lsync_async_restart_restore:
  pushq	%rax

  ENTER_RESTART (%rax)

  pushq	%rdi
  pushq	%rsi
  pushq	%rdx
  pushq	%rcx
  pushq	%r8
  pushq	%r9
  pushq	%r10
  pushq	%r11

  movq	%rcx, %rdi
  CALL_TH (%rsi, eri_live_restart_sync_async)

  /* Not RESTORE_INTERNAL_RET as mark is already zeroed.  */
  RESTORE_EXTERNAL_RET
  jmp	*TH_RESUME_RET(%rbx)

/************************************************/
/* eri_live_entry: atomic common		*/
/************************************************/

#define LABEL_ATOMIC_SIZE(sz, label) \
  LABEL_ATOMIC (_ERS_PASTE (label, sz))

#define ATOMIC_LABEL		ERI_LIVE_ATOMIC_LABEL

#define AT_REG_MEM_TAB		%r11
#define AT_REG_IDX		%rax
#define AT_REG_LOCK_LP_CNT	%rcx
#define AT_REG_MEM		%rdi
#define AT_REG_VER		%rsi
#define AT_REG_VAL		%r8
#define AT_REG_VAL_SZ		%ERI_R8
#define AT_REG_LD_RES		%rdx
#define AT_REG_LD_RES_SZ	%ERI_RDX

#define AT_LOAD_VAL		movq	PTH_VAR0(%rbx), AT_REG_VAL
#define AT_LOAD_MEM		movq	PTH_VAR1(%rbx), AT_REG_MEM

#define ATOMIC_MEM_TAB		ERI_LIVE_INTERNAL_ATOMIC_MEM_TABLE
#define AT_LOAD_MEM_TAB \
  movq	eri_live_internal + ATOMIC_MEM_TAB(%rip), AT_REG_MEM_TAB

#define AT_HASH_MEM \
  AT_LOAD_MEM;								\
  CALL_TH (%rsi, eri_live_atomic_hash_mem)

#define AT_MEM(idx)		(AT_REG_MEM_TAB, idx, 8)

#define AT_LOCK(idx) \
  AT_LOAD_MEM_TAB;							\
1:									\
  movq	$16, AT_REG_LOCK_LP_CNT;					\
  btsq	$0, AT_MEM (idx);						\
  jnc	2f;								\
  loop	1b;								\
									\
  pushq	%rax;								\
  movl	$__NR_sched_yield, %eax;					\
  syscall;								\
  popq	%rax;								\
  AT_LOAD_MEM_TAB;							\
  jmp	1b;								\
									\
2:

#define AT_LOCK_LOAD		AT_LOCK

#define AT_LOCK_STOR(idx) \
  movq	$2, AT_REG_VER;							\
  AT_LOCK (idx)

#define AT_UNLOCK(idx) \
  andb	$0xfe, AT_MEM (idx)

#define AT_UNLOCK_LOAD(idx) \
  movq	AT_MEM (idx), AT_REG_VER;					\
  AT_UNLOCK (idx);							\
  shrq	$1, AT_REG_VER

#define AT_UNLOCK_STOR(idx) \
  xaddq	AT_REG_VER, AT_MEM (idx);					\
  AT_UNLOCK (idx);							\
  shrq	$1, AT_REG_VER

#define TST_MARK_ATOMIC_COMPLETE_START(sz, label) \
  TST_MARK_COMPLETE_START (ATOMIC_LABEL (sz, label))

/************************************************/
/* eri_live_entry: atomic_load			*/
/************************************************/

#define ATOMIC_LOAD(sz) \
LABEL_ATOMIC_SIZE (sz, load):						\
  SET_COMPLETE_RESTART_START (ATOMIC_LABEL (sz, load), %rax);		\
									\
  AT_HASH_MEM;								\
  AT_LOAD_MEM;								\
									\
  AT_LOCK_LOAD (AT_REG_IDX);						\
									\
  MARK_SEC_PART_AND_CHECK_RESTART (ATOMIC_LABEL (sz, load));		\
									\
  _ERS_PASTE (mov, sz)	(AT_REG_MEM), AT_REG_LD_RES_SZ (sz);		\
LABEL_COMPLETE_START (ATOMIC_LABEL (sz, load)):				\
  TST_MARK_ATOMIC_COMPLETE_START (sz, load)				\
									\
  AT_UNLOCK_LOAD (AT_REG_IDX);						\
  movq	AT_REG_LD_RES, PTH_VAR0(%rbx);					\
  CALL_TH (%rcx, eri_live_atomic_load);					\
									\
  EXTERNAL_RET_DIR (%rdi);						\
									\
LABEL_RESTART_START (ATOMIC_LABEL (sz, load)):				\
  AT_UNLOCK (AT_REG_IDX);						\
  RESTART_RESUME_RET

/************************************************/
/* eri_live_entry: atomic_stor			*/
/************************************************/

#define ATOMIC_STOR(sz) \
LABEL_ATOMIC_SIZE (sz, stor):						\
  SET_COMPLETE_RESTART_START (ATOMIC_LABEL (sz, stor), %rax);		\
									\
  AT_HASH_MEM;								\
  AT_LOAD_VAL;								\
  AT_LOAD_MEM;								\
									\
  AT_LOCK_STOR (AT_REG_IDX);						\
									\
  MARK_SEC_PART_AND_CHECK_RESTART (ATOMIC_LABEL (sz, stor));		\
									\
  _ERS_PASTE (mov, sz)	AT_REG_VAL_SZ (sz), (AT_REG_MEM);		\
LABEL_COMPLETE_START (ATOMIC_LABEL (sz, stor)):				\
  TST_MARK_ATOMIC_COMPLETE_START (sz, stor)				\
									\
  AT_UNLOCK_STOR (AT_REG_IDX);						\
  CALL_TH (%rdx, eri_live_atomic_stor);					\
									\
  INTERNAL_RET_DIR (%rdi);						\
									\
LABEL_RESTART_START (ATOMIC_LABEL (sz, stor)):				\
  AT_UNLOCK (AT_REG_IDX);						\
  RESTART_RESUME_RET

/************************************************/
/* eri_live_entry: atomic_inc / atomic_dec	*/
/************************************************/

#define ATOMIC_INC_DEC(sz, op) \
LABEL_ATOMIC_SIZE (sz, op):						\
  SET_COMPLETE_RESTART_START (ATOMIC_LABEL (sz, op), %rax);		\
									\
  /* For rflags w/o tf.  */						\
  subq	$16, %rsp;							\
  AT_HASH_MEM;								\
  AT_LOAD_MEM;								\
									\
  addq	$8, %rsp;							\
  AT_LOCK_STOR (AT_REG_IDX);						\
									\
  MARK_SEC_PART_AND_CHECK_RESTART (ATOMIC_LABEL (sz, op));		\
									\
  popfq;								\
  _ERS_PASTE (mov, sz)	(AT_REG_MEM), AT_REG_LD_RES_SZ (sz);		\
  _ERS_PASTE (op, sz)	(AT_REG_MEM);					\
LABEL_COMPLETE_START (ATOMIC_LABEL (sz, op)):				\
  TST_MARK_ATOMIC_COMPLETE_START (sz, op)				\
  SAVE_NEW_RFLAGS (%rcx);						\
									\
  AT_UNLOCK_STOR (AT_REG_IDX);						\
  CALL_TH (%rcx, eri_live_atomic_load_stor);				\
									\
  INTERNAL_RET_DIR (%rdi);						\
									\
LABEL_RESTART_START (ATOMIC_LABEL (sz, op)):				\
  movq	TH_TOP_SAVED(%rbx), %rsp;					\
  AT_UNLOCK (AT_REG_IDX);						\
  RESTART_RESUME_RET

#define ATOMIC_INC(sz)		ATOMIC_INC_DEC (sz, inc)
#define ATOMIC_DEC(sz)		ATOMIC_INC_DEC (sz, dec)

/************************************************/
/* eri_live_entry: atomic_xchg			*/
/************************************************/

#define ATOMIC_XCHG(sz) \
LABEL_ATOMIC_SIZE (sz, xchg):						\
  SET_COMPLETE_RESTART_START (ATOMIC_LABEL (sz, xchg), %rax);		\
									\
  AT_HASH_MEM;								\
  AT_LOAD_VAL;								\
  AT_LOAD_MEM;								\
									\
  AT_LOCK_STOR (AT_REG_IDX);						\
									\
  MARK_SEC_PART_AND_CHECK_RESTART (ATOMIC_LABEL (sz, xchg));		\
									\
  _ERS_PASTE (xchg, sz)	AT_REG_VAL_SZ (sz), (AT_REG_MEM);		\
LABEL_COMPLETE_START (ATOMIC_LABEL (sz, xchg)):				\
  TST_MARK_ATOMIC_COMPLETE_START (sz, xchg)				\
									\
  AT_UNLOCK_STOR (AT_REG_IDX);						\
  movq	AT_REG_VAL, PTH_VAR0(%rbx);					\
  movq	AT_REG_VAL, AT_REG_LD_RES;					\
  CALL_TH (%rcx, eri_live_atomic_load_stor);				\
									\
  EXTERNAL_RET_DIR (%rdi);						\
									\
LABEL_RESTART_START (ATOMIC_LABEL (sz, xchg)):				\
  AT_UNLOCK (AT_REG_IDX);						\
  RESTART_RESUME_RET

/************************************************/
/* eri_live_entry: atomic_cmpxchg		*/
/************************************************/

#define ATOMIC_CMPXCHG(sz) \
LABEL_ATOMIC_SIZE (sz, cmpxchg):					\
  SET_COMPLETE_RESTART_START (ATOMIC_LABEL (sz, cmpxchg), %rax);	\
									\
  /* For rflags w/o tf.  */						\
  subq	$16, %rsp;							\
  AT_HASH_MEM;								\
  AT_LOAD_VAL;								\
  AT_LOAD_MEM;								\
									\
  addq	$8, %rsp;							\
  movq	%rax, %r10;							\
  movq	8 + STACK_RAX(%rsp), %rax;					\
  AT_LOCK_STOR (%r10);							\
									\
  MARK_SEC_PART_AND_CHECK_RESTART (ATOMIC_LABEL (sz, cmpxchg));		\
									\
  popfq;								\
  _ERS_PASTE (mov, sz)	(AT_REG_MEM), AT_REG_LD_RES_SZ (sz);		\
  _ERS_PASTE (cmpxchg, sz)	AT_REG_VAL_SZ (sz), (AT_REG_MEM);	\
LABEL_COMPLETE_START (ATOMIC_LABEL (sz, cmpxchg)):			\
  TST_MARK_ATOMIC_COMPLETE_START (sz, cmpxchg)				\
  SAVE_NEW_RFLAGS (%rcx);						\
									\
  AT_UNLOCK_STOR (%r10);						\
  movq	%rax, STACK_RAX(%rsp);						\
  CALL_TH (%rcx, eri_live_atomic_load_stor);				\
									\
  INTERNAL_RET_DIR (%rdi);						\
									\
LABEL_RESTART_START (ATOMIC_LABEL (sz, cmpxchg)):			\
  movq	TH_TOP_SAVED(%rbx), %rsp;					\
  AT_UNLOCK (%r10);							\
  RESTART_RESUME_RET

/************************************************/
/* eri_live_entry: atomic			*/
/************************************************/

#define IF_ATOMIC_SIZE(sz, label) \
  cmpq	$_ERS_ATOMIC_SIZE (sz), %r11;					\
  je	LABEL_ATOMIC_SIZE (sz, label)

 #define ATOMIC_OP(op) \
  _ERS_PASTE (ATOMIC_, op) (b);						\
  _ERS_PASTE (ATOMIC_, op) (w);						\
  _ERS_PASTE (ATOMIC_, op) (l);						\
  _ERS_PASTE (ATOMIC_, op) (q)

#define ATOMIC(op, label) \
LABEL_ATOMIC (label):							\
  LOAD_OP_RFLAGS (%rbx, %r11);						\
  IF_ATOMIC_SIZE (b, label);						\
  IF_ATOMIC_SIZE (w, label);						\
  IF_ATOMIC_SIZE (l, label);						\
  IF_ATOMIC_SIZE (q, label);						\
  jmp	.lerror;							\
									\
  ATOMIC_OP (op)

  ATOMIC (LOAD, load)
  ATOMIC (STOR, stor)
  ATOMIC (INC, inc)
  ATOMIC (DEC, dec)
  ATOMIC (XCHG, xchg)
  ATOMIC (CMPXCHG, cmpxchg)

  .size eri_live_entry, . - eri_live_entry
