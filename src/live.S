#include "recorder.h" /* ERI_STACK_SIZE */

#include "public/comm.h"
#include "public/recorder-offsets.h"

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
#define TH_TOP16		ERI_LIVE_THREAD_TOP16
#define TH_RSP			ERI_LIVE_THREAD_RSP
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

#define TH_RESTART		ERI_LIVE_THREAD_RESTART
#define TH_RESTART_START	ERI_LIVE_THREAD_RESTART_START

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

#define MARK_SEC_PART_BIT_OFFSET	3
#define MARK_SEC_PART_BIT		(1 << MARK_SEC_PART_BIT_OFFSET)

#define TRACE_FLAG_BIT_OFFSET		8
#define TRACE_FLAG_BIT			(1 << TRACE_FLAG_BIT_OFFSET)

  .data

  .align 16
  .global eri_live_thread_template
eri_live_thread_template:
  .space TH_SIZE16, 0
  .global eri_live_thread_template_text
  .global eri_live_thread_template_resume
  .global eri_live_thread_template_entry
  .global eri_live_thread_template_resume_ret
  .global eri_live_thread_template_internal_cont
  .global eri_live_thread_template_external_cont
  .global eri_live_thread_template_cont_end
  .global eri_live_thread_template_ret
  .global eri_live_thread_template_ret_end

#define RELA(off)	eri_live_thread_template + off
eri_live_thread_template_text:

eri_live_thread_template_entry:
  leaq	RELA (0)(%rip), %rbx
  jmp	*RELA (TH_ENTRY)(%rip)

  .align 16
eri_live_thread_template_internal_cont:
  movq	RELA (PTH_RBX)(%rip), %rbx
  .align 16, 0x90
eri_live_thread_template_external_cont:
  movq	$0, RELA (PTH_DIR)(%rip)
  jmp	*RELA (PTH_CONT)(%rip)
eri_live_thread_template_cont_end:

  .align 16
eri_live_thread_template_ret:
  movq	RELA (PTH_RBX)(%rip), %rbx
  jmp	*RELA (PTH_RET)(%rip)
eri_live_thread_template_ret_end:

  .align 16
eri_live_thread_template_resume:
  movq	UCTX_RBX(%rdx), %rbx
  movq	UCTX_RDX(%rdx), %rdx
  jmp	*RELA (TH_RESUME)(%rip)
  .align 16
eri_live_thread_template_resume_ret:
  movq	%rbx, RELA (PTH_RBX)(%rip)
  leaq	RELA (0)(%rip), %rbx
  jmp	*RELA (TH_RESUME_RET)(%rip)
  .text

/********************************************/

  .align
  .type eri_live_sigaction, @function
  .global eri_live_sigaction
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
  leaq	sigact(%rip), %rax
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
     2. we need to fix restart sync.
     3. we need to fix context.
  */
.lzero_mark:
  leaq	.lsync(%rip), %r11
  cmpq	%r11, %rax
  /* Continue check if we are not in lsync to lrestart_sync.  */
  jb	.lcheck_ret_from_sync
  leaq	.lrestart_sync(%rip), %r11
  cmpq	%r11, %rax
  /* Restart if we are in lsync to lrestart_sync.  */
  jb	.lcheck_restart_fix_sync
  
  /* Continue check if we are returning from sync, eri_live_thread_ret
     is only called by sync when mark is zero.
  */
.lcheck_ret_from_sync:
  cmpq	TH_THREAD_RET(%rbx), %rax
  /* Continue check if we are about to run the sync instruction when we
     are not inside eri_live_thread_ret.
  */
  jb	.lcheck_sync_inst
  cmpq	TH_THREAD_RET_END(%rbx), %rax
  /* Restart if we are inside eri_live_thread_ret.  */
  jb	.lcheck_restart_fix_sync

.lcheck_sync_inst:
  cmpq	$_ERS_OP_SYNC, PTH_OP(%rbx)
  /* Check if we are inside continue when op is not sync.  */
  jne	.lcheck_continue
  cmpq	PTH_RET(%rbx), %rax
  /* Restart if op is sync and we are at the sync instruction.  */
  je	.lcheck_restart_fix_sync
  /* When op is sync it can't be inside eri_live_thread_*_cont and dir must be zero.  */
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

  /* Check remainging code from mark zero to continue.  */
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

.lcheck_restart_fix_sync:
  movq	$MARK_SEC_PART_BIT, %r11

.lcheck_restart:
  cmpq	$ERI_SIGTRAP, %rdi
  jne	.lrestart
  cmpl	$ERI_TRAP_TRACE, SI_CODE(%rsi)
  jne	.lrestart

  /* Ignore sigtrap from single step tracing.  */
  ret

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
  /* Inform the restarter &live_thread and the interrupted rip through
     %rbx and %rip.
  */
  movq	%rbx, UCTX_RBX(%rdx)
  movq	%rax, UCTX_R11(%rdx)

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
  je	.lcheck_reset_trace_flag

  movq	TH_TOP(%rbx), %rax
  cmpq	%rax, UCTX_RSP(%rdx)
  jae	.ldone_proc_saved_flags
  movq	TH_TOP(%rbx), %rax
  subq	$ERI_STACK_SIZE, %rax 
  cmpq	%rax, UCTX_RSP(%rdx)
  jbe	.ldone_proc_saved_flags

.lcheck_reset_trace_flag:
  movq	TH_TOP(%rbx), %rax

  movq	-8(%rax), %r11
  andq	$TRACE_FLAG_BIT, %r11
  movq	%r11, TH_TRACE_FLAG(%rbx)
  andq	$~TRACE_FLAG_BIT, -8(%rax)

.ldone_proc_saved_flags:

  movq	UCTX_RBP(%rdx), %rbp
  movq	UCTX_R8(%rdx), %r8
  movq	UCTX_R9(%rdx), %r9
  movq	UCTX_R12(%rdx), %r12
  movq	UCTX_R13(%rdx), %r13
  movq	UCTX_R14(%rdx), %r14
  movq	UCTX_R15(%rdx), %r15

  /* Clear the trace flag.  */
  pushq	UCTX_RFLAGS(%rdx)
  andq	$~TRACE_FLAG_BIT, (%rsp)
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
  andq	$TRACE_FLAG_BIT, %rax
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
  /* Clear INTR, see .lxchg_complete_start.  */
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
  /* Clear INTR, see .lxchg_complete_start.  */
  movq	$0, PTH_DIR(%rbx)

  movq	PTH_CONT(%rbx), %rax
  movq	%rax, UCTX_RIP(%rdx)

.linvoke:
  movq	%rdi, TH_SIG_RDI(%rbx)

.ldo_invoke:
  // TODO fix ctx->stack
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
  movq	sigact, %rax
  jmp	*%rax
.lnested_signal_end:

.lerror:
  movq	$0, %r15
  movq	$0, (%r15)
  .size eri_live_sigaction, . - eri_live_sigaction

/********************************************/

  .align 16
  .type eri_live_entry, @function
  .global eri_live_entry
eri_live_entry:
  xchgq	%rsp, TH_RSP(%rbx)

  pushfq
  movq	$1, TH_RFLAGS_SAVED(%rbx)

  /* Do not modify stack downward after this. Some code relies on
     that %rflags without tf is stored at -8(%rsp).
  */
  pushfq
#ifndef ERI_NON_TST
  cmpq	$1, PTH_TST_SKIP_CTF(%rbx)
  je	.lskip_ctf
#endif
  andq	$~TRACE_FLAG_BIT, (%rsp)
  popfq
#ifndef ERI_NON_TST
  jmp	.ldone_ctf
.lskip_ctf:
  addq	$8, %rsp
.ldone_ctf:
#endif

  cmpq	$_ERS_OP_XCHG, PTH_OP(%rbx)
  je	.lxchg
  cmpq	$_ERS_OP_SYSCALL, PTH_OP(%rbx)
  je	.lsyscall
  cmpq	$_ERS_OP_SYNC, PTH_OP(%rbx)
  je	.lsync

  jmp	.lerror

.lxchg:
  pushq	%rax
  pushq	%r11

  leaq	.lxchg_complete_start(%rip), %rax
  movq	%rax, TH_COMPLETE_START(%rbx)

  leaq	.lrestart_xchg(%rip), %rax
  movq	%rax, TH_RESTART_START(%rbx)

  movq	PTH_VAR0(%rbx), %rax
  movq	PTH_VAR1(%rbx), %r11

  orq	$MARK_SEC_PART_BIT, PTH_MARK(%rbx)

  cmpq	$1, TH_RESTART(%rbx)
  je	.lrestart_xchg

  xchgq	%rax, (%r11)
.lxchg_complete_start:
  .global eri_tst_live_thread_xchg_complete_start
eri_tst_live_thread_xchg_complete_start:
  movq	%rax, PTH_VAR0(%rbx)

  xorq	%rax, %rax
  movq	TH_THREAD_EXTERNAL_CONT(%rbx), %r11
  /* We have to atomically set dir to cnt if no signal yet, because signal
     can happen between any two instructions, so we have to keep dir
     zero when we leave this place. There are three possible ways leaving
     here: 1, no signal, dir is cleared in cnt, 2, signal before setting
     mark to 0, dir is cleared in gintr, 3, signal after, dir is cleared
     in fix
  */
  cmpxchgq	%r11, PTH_DIR(%rbx)

  popq	%r11
  popq	%rax
  movq	$0, TH_RFLAGS_SAVED(%rbx)
  popfq
  xchgq	TH_RSP(%rbx), %rsp
  jmp	*TH_THREAD_RET(%rbx)

.lrestart_xchg:
  movq	PTH_START(%rbx), %rax
  movq	%rax, PTH_CONT(%rbx)
  movq	$0, TH_RESTART(%rbx)
  popq	%r11
  popq	%rax
  movq	$0, TH_RFLAGS_SAVED(%rbx)
  popfq
  xchgq	%rsp, TH_RSP(%rbx)
  movq	$0, PTH_MARK(%rbx)
  jmp	*TH_RESUME_RET(%rbx)

.lsyscall:
  /* %rflags without tf is stored at -8(%rsp).  */
  subq	$8, %rsp
  xchgq	(%rsp), %r11
  pushq	%r11

  /* top ---
	 rflags
	 r11
	 rflags w/o tf
     rsp ---
  */

  leaq	.lsyscall_complete_start(%rip), %r11
  movq	%r11, TH_COMPLETE_START(%rbx)

  leaq	.lrestart_syscall(%rip), %r11
  movq	%r11, TH_RESTART_START(%rbx)

  orq	$MARK_SEC_PART_BIT, PTH_MARK(%rbx)

  cmpq	$1, TH_RESTART(%rbx)
  je	.lrestart_syscall

  popfq
  movq	TH_RSP(%rbx), %rsp
  syscall
.lsyscall_complete_start:
  .global eri_tst_live_thread_syscall_complete_start
eri_tst_live_thread_syscall_complete_start:
  movq	TH_TOP16(%rbx), %rsp
  movq	%r11, (%rsp)
  pushq	%rax

  pushfq
  popq	%rax


  /* Reset tf.
     top ---
	 rflags
	 r11
	 rax
     rsp ---

     r11 = (rflags & TF_MASK) | r11
     rflags = (rflags & TF_MASK) | (new_rflags & ~TF_MASK)

     Setting rflags has to be like this. We can't move rflags
     out of stack or clear tf code in lresume may not work.
  */
  andq	$TRACE_FLAG_BIT, 16(%rsp)
#ifndef ERI_NON_TST
  /* May also not required if tst_skip_ctf is 0.  */
  andq	$~TRACE_FLAG_BIT, %rax 
  andq	$~TRACE_FLAG_BIT, 8(%rsp)
#endif
  orq	%rax, 16(%rsp)

  movq	16(%rsp), %rax
  andq	$TRACE_FLAG_BIT, %rax
  orq	%rax, 8(%rsp)

  xorq	%rax, %rax
  movq	TH_THREAD_INTERNAL_CONT(%rbx), %r11
  /* See .lxchg_complete_start.  */
  cmpxchgq	%r11, PTH_DIR(%rbx)

  popq	%rax
  popq	%r11
  movq	$0, TH_RFLAGS_SAVED(%rbx)
  popfq
  xchgq	TH_RSP(%rbx), %rsp
  movq	$0, PTH_MARK(%rbx)
  jmp	*PTH_DIR(%rbx)

.lrestart_syscall:
  movq	TH_TOP16(%rbx), %rsp

  movq	PTH_START(%rbx), %r11
  movq	%r11, PTH_CONT(%rbx)
  movq	$0, TH_RESTART(%rbx)

  popq	%r11
  movq	$0, TH_RFLAGS_SAVED(%rbx)
  popfq
  xchgq	%rsp, TH_RSP(%rbx)
  movq	$0, PTH_MARK(%rbx)
  jmp	*TH_RESUME_RET(%rbx)

.lsync:
  pushq	%rax
  pushq	%r11
  leaq	.lrestart_sync(%rip), %rax
  movq	%rax, TH_RESTART_START(%rbx)

  xorq	%r11, %r11
  movq	$0, PTH_MARK(%rbx)

  cmpq	$1, TH_RESTART(%rbx)
  je	.lrestart_sync

  popq	%r11
.lsync1:
  popq	%rax
.lsync2:

  movq	$0, TH_RFLAGS_SAVED(%rbx)
  popfq
.lsync3:
  xchgq	TH_RSP(%rbx), %rsp
.lsync4:
  jmp	*TH_THREAD_RET(%rbx)

.lrestart_sync:
  /* TODO check rcx for rep.  */
  testq	%r11, %r11
  jz	.lrestart_sync_restore0

  leaq	.lsync(%rip), %rax
  cmpq	%rax, %r11
  jb	.lrestart_sync_restore4

  leaq	.lsync1(%rip), %rax
  cmpq	%rax, %r11
  jb	.lrestart_sync_restore0

  leaq	.lsync2(%rip), %rax
  cmpq	%rax, %r11
  jb	.lrestart_sync_restore1

  leaq	.lsync3(%rip), %rax
  cmpq	%rax, %r11
  jb	.lrestart_sync_restore2

  leaq	.lsync4(%rip), %rax
  cmpq	%rax, %r11
  jb	.lrestart_sync_restore3
  jmp	.lrestart_sync_restore4

.lrestart_sync_restore4:
  xchgq	%rsp, TH_RSP(%rbx)
.lrestart_sync_restore3:
  subq	$8, %rsp
  movq	(%rsp), %rax
  andq	$~TRACE_FLAG_BIT, (%rsp)
  andq	$TRACE_FLAG_BIT, %rax
  movq	%rax, TH_TRACE_FLAG(%rbx)
.lrestart_sync_restore2:
  subq	$8, %rsp
.lrestart_sync_restore1:
  subq	$8, %rsp

.lrestart_sync_restore0:
  movq	PTH_START(%rbx), %rax
  movq	%rax, PTH_CONT(%rbx)

  movq	$0, TH_RESTART(%rbx)

  popq	%r11
  popq	%rax
  movq	$0, TH_RFLAGS_SAVED(%rbx)
  popfq
  xchgq	TH_RSP(%rbx), %rsp

  jmp	*TH_RESUME_RET(%rbx)

  .size eri_live_entry, . - eri_live_entry
