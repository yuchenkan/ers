/* vim: set ft=gas: */

#include "public/common.h"
#include "public/entry-offsets.h"

#include "rtld-offsets.h"
#include "live-entry.h"
#include "live-entry-offsets.h"

#include "lib/util.h"
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

#define PTE_MARK		_ERS_THREAD_ENTRY_MARK
#define PTE_OP			_ERS_THREAD_ENTRY_OP

#define PTE_START		_ERS_THREAD_ENTRY_START
#define PTE_RET			_ERS_THREAD_ENTRY_RET
#define PTE_CONT		_ERS_THREAD_ENTRY_CONT

#define PTE_DIR			_ERS_THREAD_ENTRY_DIR

#define PTE_RBX			_ERS_THREAD_ENTRY_RBX
#define PTE_VAR0		_ERS_THREAD_ENTRY_VAR0
#define PTE_VAR1		_ERS_THREAD_ENTRY_VAR1

#define PTE_THREAD_ENTRY	_ERS_THREAD_ENTRY_THREAD_ENTRY
#define TE_ENTRY		ERI_LIVE_THREAD_ENTRY_ENTRY

#define TE_TOP			ERI_LIVE_THREAD_ENTRY_TOP
#define TE_TOP_SAVED		ERI_LIVE_THREAD_ENTRY_TOP_SAVED
#define TE_RSP			ERI_LIVE_THREAD_ENTRY_RSP
#define TE_STACK_SIZE		ERI_LIVE_THREAD_ENTRY_STACK_SIZE
#define TE_RFLAGS_SAVED		ERI_LIVE_THREAD_ENTRY_RFLAGS_SAVED
#define TE_TRACE_FLAG		ERI_LIVE_THREAD_ENTRY_TRACE_FLAG

#define TE_THREAD_INTERNAL_CONT	ERI_LIVE_THREAD_ENTRY_THREAD_INTERNAL_CONT
#define TE_THREAD_EXTERNAL_CONT	ERI_LIVE_THREAD_ENTRY_THREAD_EXTERNAL_CONT
#define TE_THREAD_CONT_END	ERI_LIVE_THREAD_ENTRY_THREAD_CONT_END

#define TE_THREAD_RET		ERI_LIVE_THREAD_ENTRY_THREAD_RET
#define TE_THREAD_RET_END	ERI_LIVE_THREAD_ENTRY_THREAD_RET_END

#define TE_THREAD_RESUME	ERI_LIVE_THREAD_ENTRY_THREAD_RESUME
#define TE_RESUME		ERI_LIVE_THREAD_ENTRY_RESUME
#define TE_THREAD_RESUME_RET	ERI_LIVE_THREAD_ENTRY_THREAD_RESUME_RET
#define TE_RESUME_RET		ERI_LIVE_THREAD_ENTRY_RESUME_RET

#define TE_COMPLETE_START	ERI_LIVE_THREAD_ENTRY_COMPLETE_START

#define TE_FIX_RESTART		ERI_LIVE_THREAD_ENTRY_FIX_RESTART
#define TE_FIX_RESTART_RAX	ERI_LIVE_THREAD_ENTRY_FIX_RESTART_RAX
#define TE_FIX_RESTART_RBX	ERI_LIVE_THREAD_ENTRY_FIX_RESTART_RBX
#define TE_FIX_RESTART_RIP	ERI_LIVE_THREAD_ENTRY_FIX_RESTART_RIP
#define TE_FIX_RESTART_RFLAGS	ERI_LIVE_THREAD_ENTRY_FIX_RESTART_RFLAGS

#define TE_RESTART		ERI_LIVE_THREAD_ENTRY_RESTART
#define TE_RESTART_START	ERI_LIVE_THREAD_ENTRY_RESTART_START

#define TE_EXT_RBP		ERI_LIVE_THREAD_ENTRY_EXT_RBP
#define TE_EXT_R12		ERI_LIVE_THREAD_ENTRY_EXT_R12
#define TE_EXT_R13		ERI_LIVE_THREAD_ENTRY_EXT_R13
#define TE_EXT_R14		ERI_LIVE_THREAD_ENTRY_EXT_R14
#define TE_EXT_R15		ERI_LIVE_THREAD_ENTRY_EXT_R15

#define TE_SYSCALL_RSP		ERI_LIVE_THREAD_ENTRY_SYSCALL_RSP
#define TE_SYSCALL_NEW_THREAD	ERI_LIVE_THREAD_ENTRY_SYSCALL_NEW_THREAD
#define TE_SYNC_REPEAT_TRACE	ERI_LIVE_THREAD_ENTRY_SYNC_REPEAT_TRACE

#define TE_SIG_RBX		ERI_LIVE_THREAD_ENTRY_SIG_RBX
#define TE_SIG_RDI		ERI_LIVE_THREAD_ENTRY_SIG_RDI
#define TE_SIG_RSI		ERI_LIVE_THREAD_ENTRY_SIG_RSI
#define TE_SIG_RDX		ERI_LIVE_THREAD_ENTRY_SIG_RDX
#define TE_SIG_RSP		ERI_LIVE_THREAD_ENTRY_SIG_RSP
#define TE_SIG_RBP		ERI_LIVE_THREAD_ENTRY_SIG_RBP
#define TE_SIG_R12		ERI_LIVE_THREAD_ENTRY_SIG_R12
#define TE_SIG_R13		ERI_LIVE_THREAD_ENTRY_SIG_R13
#define TE_SIG_R14		ERI_LIVE_THREAD_ENTRY_SIG_R14
#define TE_SIG_R15		ERI_LIVE_THREAD_ENTRY_SIG_R15

#define TE_SIG_STACK		ERI_LIVE_THREAD_ENTRY_SIG_STACK

#define TE_THREAD		ERI_LIVE_THREAD_ENTRY_THREAD

#define PTE_TST_SKIP_CTF	ERI_LIVE_THREAD_ENTRY_TST_SKIP_CTF

#define TE_SIZE16		ERI_LIVE_THREAD_ENTRY_SIZE16

#define PASTE			_ERS_PASTE
#define PASTE2			_ERS_PASTE2

#define LABEL(name)			PASTE (.L, name)
#define PREFIX_LABEL(prefix, name)	LABEL (PASTE (prefix, name))
#define SUFFIX_LABEL(name, suffix)	LABEL (PASTE (name, suffix))
#define COMPLETE_START_LABEL(name)	SUFFIX_LABEL (name, _complete_start)
#define RESTART_START_LABEL(name)	SUFFIX_LABEL (name, _restart_start)

#define MARK_SEC_PART_BIT_OFFSET \
  ERI_LIVE_ENTRY_MARK_SEC_PART_BIT_OFFSET
#define MARK_SEC_PART_BIT		ERI_LIVE_ENTRY_MARK_SEC_PART_BIT

#define MOV_MM(src, dst, reg) \
  movq	src, reg;							\
  movq	reg, dst

#define CMP_MM(src, dst, reg) \
  movq	src, reg;							\
  cmpq	reg, dst

#define LOAD_OP_OP(dst) \
  movq	PTE_OP(%rbx), dst;						\
  shrq	$_ERS_OP_FLAGS_BITS, dst

#define LOAD_OP_RFLAGS(dst) \
  movq	PTE_OP(%rbx), dst;						\
  andq	$_ERS_OP_FLAGS_MASK, dst

#define RESTORE_SIG_MASK(...) \
  movl	$__NR_rt_sigprocmask, %eax;					\
  movq	$ERI_SIG_SETMASK, %rdi;						\
  __VA_ARGS__								\
  xorq	%rdx, %rdx;							\
  movq	$ERI_SIG_SETSIZE, %r10;						\
  syscall

#define CHECK_RESTORE_SIG_MASK(...) \
  RESTORE_SIG_MASK (__VA_ARGS__);					\
  testq	%rax, %rax;							\
  jnz	.lerror

/************************************************/
/* eri_live_thread_entry_text			*/
/************************************************/

  .data

ERI_GLOBAL_HIDDEN (eri_live_entry_atomic_mem_table)
  .long 0

  .align 16
ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text)
#define RELA(off)	eri_live_thread_entry_text - TE_SIZE16 + off

ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text_entry)
  leaq	RELA (0)(%rip), %rbx
  jmp	*RELA (TE_ENTRY)(%rip)

  .align 16
ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text_internal_cont)
  movq	RELA (PTE_RBX)(%rip), %rbx
  .align 16, 0x90
ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text_external_cont)
  movq	$0, RELA (PTE_DIR)(%rip)
  jmp	*RELA (PTE_CONT)(%rip)
ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text_cont_end)

  .align 16
ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text_ret)
  movq	RELA (PTE_RBX)(%rip), %rbx
  jmp	*RELA (PTE_RET)(%rip)
ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text_ret_end)

  .align 16
ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text_resume)
  movq	UCTX_RBX(%rdx), %rbx
  movq	UCTX_RDX(%rdx), %rdx
  jmp	*RELA (TE_RESUME)(%rip)
  .align 16
ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text_resume_ret)
  movq	%rbx, RELA (PTE_RBX)(%rip)
  leaq	RELA (0)(%rip), %rbx
  jmp	*RELA (TE_RESUME_RET)(%rip)

  .align 16
ERI_GLOBAL_HIDDEN (eri_live_thread_entry_text_end)

  .text

/************************************************/
/* eri_live_entry_sigaction			*/
/************************************************/

ERI_GLOBAL_HIDDEN_FUNCTION (eri_live_entry_sigaction)

  movq	UCTX_SS_SP(%rdx), %rax
  movq	(%rax), %rax
  movq	%rbx, TE_SIG_RBX(%rax)
  /* %rbx is &live_thread.  */
  movq	%rax, %rbx

  /* %rax is the interrupted rip.  */
  movq	UCTX_RIP(%rdx), %rax

#define CMP_RIP_F(field) \
  cmpq	field(%rbx), %rax
#define CMP_RIP_L(label) \
  leaq	label(%rip), %r11;						\
  cmpq	%r11, %rax

#define IF_RIP_IN_RANGE(min_type, min, max_type, max, true) \
  PASTE (CMP_RIP_, min_type) (min);					\
  jb	1f;								\
  PASTE (CMP_RIP_, max_type) (max);					\
  jb	true;								\
1:

#define IF_RIP_IN_RANGE_FF(min, max, true) \
  IF_RIP_IN_RANGE (F, min, F, max, true)
#define IF_RIP_IN_RANGE_FL(min, max, true) \
  IF_RIP_IN_RANGE (F, min, L, max, true)
#define IF_RIP_IN_RANGE_LF(min, max, true) \
  IF_RIP_IN_RANGE (L, min, F, max, true)
#define IF_RIP_IN_RANGE_LL(min, max, true) \
  IF_RIP_IN_RANGE (L, min, L, max, true)

  /* Check nested signal.  */
  IF_RIP_IN_RANGE_LL (.lnested_signal_start, .lnested_signal_end,
		      .lnested_signal)

  movq	PTE_MARK(%rbx), %r11
  testq	%r11, %r11
  jz	.lzero_mark

  bt	$MARK_SEC_PART_BIT_OFFSET, %r11
  /* ! (mark & MARK_SEC_PART_BIT) means we need to restart.  */
  jnc	.lrestart_check_trace

  /* Otherwise means we may restart or complete. */

  /* Restart if we are inside do_syscall but not done the syscall.  */
  IF_RIP_IN_RANGE_LL (eri_live_entry_do_syscall,
		      COMPLETE_START_LABEL (do_syscall),
		      .lrestart_check_trace)

  /* Restart if we are inside eri_live_entry but not done the
     target instruction.
  */
  IF_RIP_IN_RANGE_LF (eri_live_entry, TE_COMPLETE_START,
		      .lrestart_check_trace)

  /* Complete internally, we don't return to the user code.  */
  cmpq	$MARK_SEC_PART_BIT | _ERS_MARK_INTERNAL_RET, PTE_MARK(%rbx)
  je	.linternal_complete
  /* Complete externally.  */
  movq	TE_THREAD_RESUME_RET(%rbx), %rax
  jmp	.lcomplete_resume
.linternal_complete:
  movq	TE_RESUME_RET(%rbx), %rax
.lcomplete_resume:
  movq	%rax, PTE_DIR(%rbx)
  jmp	.lresume

  /* 1. we are in user code.
     2. we need to fix restart sync_async.
     3. we need to fix context.
  */
.lzero_mark:
  /* Restart if we are inside sync_async.  */
  IF_RIP_IN_RANGE_LL (.lsync_async, RESTART_START_LABEL (sync_async),
		      .lrestart_fix_sync_async_check_trace)

  /* Restart if we are inside eri_live_thread_entry_ret.  */
  IF_RIP_IN_RANGE_FF (TE_THREAD_RET, TE_THREAD_RET_END,
		      .lrestart_fix_sync_async_check_trace)

  /* Continue check if we are about to run the sync_async instruction when we
     are not inside eri_live_thread_entry_ret.
  */
  LOAD_OP_OP (%r11)
  cmpq	$_ERS_OP_SYNC_ASYNC, %r11
  /* Check if we are inside continue when op is not sync_async.  */
  jne	.lcheck_continue
  cmpq	PTE_RET(%rbx), %rax
  /* Restart if op is sync_async and we are at the sync_async
     instruction.
  */
  je	.lrestart_fix_sync_async_inst_check_trace

  /* Invoke user sigaction without further check. when op is sync_async
     it can't be inside eri_live_thread_entry_*_cont and dir also must
     be zero.
  */
  jmp	.linvoke

.lcheck_continue:
  cmpq	TE_THREAD_INTERNAL_CONT(%rbx), %rax
  /* Check remaining code from mark zero to continue
     if we are not in eri_live_thread_entry_*_cont.
  */
  jb	.lcheck_remaining
  /* Fix context internally if at eri_live_thread_entry_internal_cont.  */
  je	.linternal_fix
  cmpq	TE_THREAD_CONT_END(%rbx), %rax
  /* Fix context externally if in eri_live_thread_entry_external_cont.  */
  jb	.lfix

  /* Check remainging code from mark zero to continue by checking dir
     field.
  */
.lcheck_remaining:
  movq	PTE_DIR(%rbx), %r11
  testq	%r11, %r11
  /* Invoke sigaction if continue address is zero.  */
  jz	.linvoke
  cmpq	TE_THREAD_INTERNAL_CONT(%rbx), %r11
  /* Fix internally if is eri_live_thread_entry_internal_cont.  */
  je	.linternal_fix
  cmpq	TE_THREAD_EXTERNAL_CONT(%rbx), %r11
  /* Fix externally if is eri_live_thread_entry_external_cont.  */
  jmp	.lfix

.lnested_signal:
  /* Nested signal, complete the context for the old signal
     and invoke.
  */
#define NESTED_FIX(reg) \
  MOV_MM (PASTE (TE_SIG_, reg)(%rbx), PASTE (UCTX_, reg)(%rdx), %rax)

  NESTED_FIX (RBX)
  NESTED_FIX (RDI)
  NESTED_FIX (RSI)
  NESTED_FIX (RDX)
  jmp	.linvoke

/* Check sigtrap from single step tracing.  */
#define IF_NOT_TRACE(not_trace) \
  cmpq	$ERI_SIGTRAP, %rdi;						\
  jne	not_trace;							\
  cmpl	$ERI_TRAP_TRACE, SI_CODE(%rsi);					\
  jne	not_trace

#define SIGRETURN \
  addq	$8, %rsp;							\
  jmp	eri_sigreturn

/* Ignore sigtrap from single step tracing.  */
#define IGNORE_TRACE(not_trace) \
  IF_NOT_TRACE (not_trace);						\
  SIGRETURN

.lrestart_fix_sync_async_check_trace:
  IGNORE_TRACE (.lfix_restart)

.lrestart_fix_sync_async_inst_check_trace:
  IF_NOT_TRACE (.lfix_restart)
  cmpq	$0, TE_SYNC_REPEAT_TRACE(%rbx)
  jne	.lfix_restart
  movq	$1, TE_SYNC_REPEAT_TRACE(%rbx)
  SIGRETURN

.lrestart_check_trace:
  IGNORE_TRACE (.lrestart)

  /* We are done all the branching.  */

.lrestart:
  bt	$MARK_SEC_PART_BIT_OFFSET, PTE_MARK(%rbx)
  /* We are in the second part while the instrcution is not reached.
     We still restart the instruction but we need to manully fix the
     context to let the interrupted code know where they are before
     we resume those code.
  */
  jc	.lfix_restart

  /* We are in the safe place, just mark and let the interrupted code
     do the restart.
  */
  movq	$1, TE_RESTART(%rbx)
  jmp	.lresume

.lfix_restart:
  movq	$1, TE_FIX_RESTART(%rbx)
  MOV_MM (UCTX_RBX(%rdx), TE_FIX_RESTART_RBX(%rbx), %r11)
  movq	%rbx, UCTX_RBX(%rdx)
  movq	%rax, TE_FIX_RESTART_RIP(%rbx)
  movq	UCTX_RFLAGS(%rdx), %r11
  andq	$~ERI_TRACE_FLAG_MASK, %r11
  movq	%r11, TE_FIX_RESTART_RFLAGS(%rbx)

  /* Resume to the restarter.  */
  MOV_MM (TE_RESTART_START(%rbx), UCTX_RIP(%rdx), %rax)

  /* Save the current context and return to the (possibly fixed)
     interrupted context.
  */
.lresume:
  movq	%rdi, TE_SIG_RDI(%rbx)
  movq	%rsi, TE_SIG_RSI(%rbx)
  movq	%rdx, TE_SIG_RDX(%rbx)
  movq	%rsp, TE_SIG_RSP(%rbx)

  movq	%rbp, TE_SIG_RBP(%rbx)
  movq	%r12, TE_SIG_R12(%rbx)
  movq	%r13, TE_SIG_R13(%rbx)
  movq	%r14, TE_SIG_R14(%rbx)
  movq	%r15, TE_SIG_R15(%rbx)

  MOV_MM (UCTX_RIP(%rdx), TE_RESUME(%rbx), %rax)

  /* We are try to reset the trace flag saved on the stack so tracing won't
     be restored by popfq to avoid recursive sigtrap.
  */
  movq	$0, TE_TRACE_FLAG(%rbx)

  cmpq	$1, TE_RFLAGS_SAVED(%rbx)
  je	.lresume_check_reset_trace_flag

  CMP_MM (TE_TOP(%rbx), UCTX_RSP(%rdx), %rax)
  jae	.lresume_done_proc_saved_flags
  movq	TE_TOP(%rbx), %rax
  subq	TE_STACK_SIZE(%rbx), %rax
  cmpq	%rax, UCTX_RSP(%rdx)
  jbe	.lresume_done_proc_saved_flags

.lresume_check_reset_trace_flag:
  movq	TE_TOP(%rbx), %rax

  movq	-8(%rax), %r11
  andq	$ERI_TRACE_FLAG_MASK, %r11
  movq	%r11, TE_TRACE_FLAG(%rbx)
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

  jmp	*TE_THREAD_RESUME(%rbx)

  /* %rbx is live_thread_entry, the interrupted %rbx is saved in RBX.
     %rip is saved in CNT. %rflags is the interrupted %rflags & ~tf,
     All other regs are not modified.
  */
  ERI_GLOBAL_HIDDEN (eri_live_resume_ret)
eri_live_resume_ret:
  /* Modify the context based on the new register values.  */
  xchgq	%rsp, TE_RSP(%rbx)
  pushq	%rdx
  movq	TE_SIG_RDX(%rbx), %rdx
  movq	%rax, UCTX_RAX(%rdx)
  MOV_MM (PTE_RBX(%rbx), UCTX_RBX(%rdx), %rax)
  movq	%rcx, UCTX_RCX(%rdx)
  popq	%rax
  movq	%rax, UCTX_RDX(%rdx)
  movq	%rsi, UCTX_RSI(%rdx)
  movq	%rdi, UCTX_RDI(%rdx)
  MOV_MM (TE_RSP(%rbx), UCTX_RSP(%rdx), %rax)
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
  orq	TE_TRACE_FLAG(%rbx), %rax
  orq	%rax, UCTX_RFLAGS(%rdx)
  /* Set trace flag in r11 accordingly if op is syscall, and
     we are not restarting or holding (see lsyscall).
  */
  LOAD_OP_OP (%r11)
  cmpq	$_ERS_OP_SYSCALL, %r11
  jne	.ldone_restore_trace_flag
  CMP_MM (PTE_START(%rbx), PTE_CONT(%rbx), %r11)
  je	.ldone_restore_trace_flag
  orq	%rax, UCTX_R11(%rdx)
.ldone_restore_trace_flag:

  MOV_MM (PTE_CONT(%rbx), UCTX_RIP(%rdx), %rax)

  /* Set rsp to top again.  */
  movq	%rsp, TE_RSP(%rbx)
  movq	$0, TE_FIX_RESTART(%rbx)

  movq	TE_SIG_RBP(%rbx), %rbp
  movq	TE_SIG_R12(%rbx), %r12
  movq	TE_SIG_R13(%rbx), %r13
  movq	TE_SIG_R14(%rbx), %r14
  movq	TE_SIG_R15(%rbx), %r15

  movq	TE_SIG_RDI(%rbx), %rdi
  movq	TE_SIG_RSI(%rbx), %rsi
  movq	TE_SIG_RSP(%rbx), %rsp
  /* Clear INTR, see CHECK_SET_DIR.  */
  movq	$0, PTE_DIR(%rbx)

  /* Ignore the fisrt trace of new threads.  */
  IF_NOT_TRACE (.ldo_invoke)
  LOAD_OP_OP (%rax)
  cmpq	$_ERS_OP_SYSCALL, %rax
  jne	.ldo_invoke
  cmpq	$1, TE_SYSCALL_NEW_THREAD(%rbx)
  jne	.ldo_invoke
  SIGRETURN

.linternal_fix:
  /* The only difference between internal and external is %rbx
     is restored if we run externally to make modifing %rbx is
     visible, internally we keep %rbx &live_thread to make jumps
     possible.
  */
  MOV_MM (PTE_RBX(%rbx), UCTX_RBX(%rdx), %rax)

.lfix:
  /* Clear INTR, see CHECK_SET_DIR.  */
  movq	$0, PTE_DIR(%rbx)
  MOV_MM (PTE_CONT(%rbx), UCTX_RIP(%rdx), %rax)

.linvoke:
  movq	%rdi, TE_SIG_RDI(%rbx)

#define SIGACTION_RSI		ERI_LIVE_ENTRY_SIGACTION_INFO_RSI
#define SIGACTION_RDX		ERI_LIVE_ENTRY_SIGACTION_INFO_RDX
#define SIGACTION_RSP		ERI_LIVE_ENTRY_SIGACTION_INFO_RSP
#define SIGACTION_RIP		ERI_LIVE_ENTRY_SIGACTION_INFO_RIP
#define SIGACTION_MASK_ALL	ERI_LIVE_ENTRY_SIGACTION_INFO_MASK_ALL
#define SIGACTION_MASK		ERI_LIVE_ENTRY_SIGACTION_INFO_MASK
#define SIGACTION_SIZE16	ERI_LIVE_ENTRY_SIGACTION_INFO_SIZE16

.ldo_invoke:
  movq	UCTX_SS_SP(%rdx), %rcx
  movq	%rsp, %r8
  subq	$SIGACTION_SIZE16 + 8, %rsp
  call	eri_live_entry_start_sigaction

  cmpb	$1, SIGACTION_MASK_ALL(%rsp)
  je	.lfast_invoke

  MOV_MM (SIGACTION_RSI(%rsp), TE_SIG_RSI(%rbx), %rax)
  MOV_MM (SIGACTION_RDX(%rsp), TE_SIG_RDX(%rbx), %rax)

  movq	SIGACTION_RIP(%rsp), %r8

  leaq	SIGACTION_MASK(%rsp), %rsi
  movq	SIGACTION_RSP(%rsp), %rsp

  RESTORE_SIG_MASK ()
.lnested_signal_start:
  testq	%rax, %rax
  jnz	.lerror
  movq	TE_SIG_RDI(%rbx), %rdi
  movq	TE_SIG_RSI(%rbx), %rsi
  movq	TE_SIG_RDX(%rbx), %rdx
  movq	TE_SIG_RBX(%rbx), %rbx
  jmp	*%r8
.lnested_signal_end:

.lfast_invoke:
  movq	TE_SIG_RDI(%rbx), %rdi
  movq	TE_SIG_RBX(%rbx), %rbx
  movq	SIGACTION_RSI(%rsp), %rsi
  movq	SIGACTION_RDX(%rsp), %rdx
  movq	SIGACTION_RIP(%rsp), %rax
  movq	SIGACTION_RSP(%rsp), %rsp
  jmp	*%rax

.lerror:
  ERI_ASSERT_FALSE
  .size eri_live_entry_sigaction, . - eri_live_entry_sigaction

/************************************************/
/* eri_live_entry_start				*/
/************************************************/

ERI_GLOBAL_HIDDEN_FUNCTION (eri_live_entry_start)

  movq	%rdi, %rbx
  movq	%rsi, %r8

#define INSTALL_ENTRY \
  movl	$__NR_arch_prctl, %eax;						\
  movq	$ERI_ARCH_SET_GS, %rdi;						\
  movq	%rbx, %rsi;							\
  syscall;								\
  testq	%rax, %rax;							\
  jnz	.lerror

  INSTALL_ENTRY

#define SIGALTSTACK_NO_RESTORE \
  subq	$ERI_STACK_SIZE16, %rsp;					\
  MOV_MM (TE_SIG_STACK(%rbx), ERI_STACK_SP(%rsp), %rax);		\
  movq	$0, ERI_STACK_FLAGS(%rsp);					\
  movq	$ERI_LIVE_SIG_STACK_SIZE, ERI_STACK_SIZE(%rsp);			\
									\
  movl	$__NR_sigaltstack, %eax;					\
  movq	%rsp, %rdi;							\
  xorq	%rsi, %rsi;							\
  syscall;								\
  testq	%rax, %rax;							\
  jnz	.lerror

#define SIGALTSTACK \
  SIGALTSTACK_NO_RESTORE;						\
  addq	$ERI_STACK_SIZE16, %rsp

  SIGALTSTACK_NO_RESTORE

  movq	ERI_RTLD_RDX(%r8), %r9
  movq	ERI_RTLD_RSP(%r8), %rsp
  MOV_MM (ERI_RTLD_RIP(%r8), PTE_CONT(%rbx), %rax)
  movq	$0, PTE_RBX(%rbx)
  MOV_MM (TE_THREAD_INTERNAL_CONT(%rbx), PTE_DIR(%rbx), %rax)

  xorq	%rbp, %rbp
  xorq	%r12, %r12
  xorq	%r13, %r13
  xorq	%r14, %r14
  xorq	%r15, %r15

  movq	$_ERS_MARK_INTERNAL_RET | MARK_SEC_PART_BIT, PTE_MARK(%rbx)

  cmpb	$1, ERI_RTLD_SIG_MASK_ALL(%r8)
  je	.lfast_start_return

  CHECK_RESTORE_SIG_MASK (leaq	ERI_RTLD_SIG_MASK(%r8), %rsi;)
.lfast_start_return:

  movq	%r9, %rdx

  xorq	%rsi, %rsi
  xorq	%r8, %r8
  xorq	%r9, %r9
  xorq	%r10, %r10
  xorq	%r11, %r11

  movq	%rsp, %rdi
  subq	$8192, %rdi
  movq	$1024, %rcx
  rep stosq

  xorq	%rcx, %rcx
  xorq	%rdi, %rdi

  popfq
  movq	$0, -8(%rsp)

  movq	$0, PTE_MARK(%rbx)
  jmp	*PTE_DIR(%rbx)

  .size eri_live_entry_start, . - eri_live_entry_start


/************************************************/
/* eri_live_entry				*/
/************************************************/

ERI_GLOBAL_HIDDEN_FUNCTION (eri_live_entry)
  xchgq	%rsp, TE_RSP(%rbx)

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
  cmpq	$1, PTE_TST_SKIP_CTF(%rbx)
  je	.ltst_skip_ctf
#endif
  andq	$~ERI_TRACE_FLAG_MASK, (%rsp)
  popfq
  subq	$8, %rsp
#ifndef ERI_NON_TST
.ltst_skip_ctf:
#endif

  popq	-ERI_LIVE_ENTRY_SAVED_REG_SIZE16(%rsp) /* STACK_RFLAGS_CTF */

  movq	$1, TE_RFLAGS_SAVED(%rbx)

  pushq	%rax
  pushq	%rdi
  pushq	%rsi
  pushq	%rdx
  pushq	%rcx
  pushq	%r8
  pushq	%r9
  pushq	%r10
  pushq	%r11	/* top - ERI_LIVE_ENTRY_SAVED_REG_SIZE16 */

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
  movq	$0, TE_RFLAGS_SAVED(%rbx);					\
  popfq

#define RESTORE_EXTERNAL_RET \
  RESTORE_GENERAL_REGS;							\
  RESTORE_RFLAGS;							\
  xchgq	TE_RSP(%rbx), %rsp

#define RESTORE_INTERNAL_RET \
  RESTORE_EXTERNAL_RET;							\
  movq	$0, PTE_MARK(%rbx)

#define STACK_RFLAGS_CTF	-8

  LOAD_OP_OP (%r11)

  cmpq	$_ERS_OP_SYSCALL, %r11
  je	.lsyscall
  cmpq	$_ERS_OP_SYNC_ASYNC, %r11
  je	.lsync_async

#define ATOMIC_LABEL(name)	PREFIX_LABEL (atomic_, name)

/* %r11 is op.  */
#define IF_ATOMIC(op, name) \
  cmpq	$PASTE (_ERS_OP_ATOMIC_, op), %r11;				\
  je	ATOMIC_LABEL (name)

  IF_ATOMIC (LOAD, load)
  IF_ATOMIC (STORE, store)
  IF_ATOMIC (INC, inc)
  IF_ATOMIC (DEC, dec)
  IF_ATOMIC (XCHG, xchg)
  IF_ATOMIC (CMPXCHG, cmpxchg)

  jmp	.lerror

#define SET_LABEL_FIELD(label, field, reg) \
  leaq	label(%rip), reg;						\
  movq	reg, field(%rbx)

#define SET_COMPLETE_START(name, reg) \
  SET_LABEL_FIELD (COMPLETE_START_LABEL (name), TE_COMPLETE_START, reg)

#define SET_RESTART_START(name, reg) \
  SET_LABEL_FIELD (RESTART_START_LABEL (name), TE_RESTART_START, reg)

#define SET_COMPLETE_RESTART_START(name, reg) \
  SET_COMPLETE_START (name, reg);					\
  SET_RESTART_START (name, reg)

#define CHECK_RESTART(name) \
  cmpq	$1, TE_RESTART(%rbx);						\
  je	RESTART_START_LABEL (name)

#define MARK_SEC_PART_AND_CHECK_RESTART(name) \
  orq	$MARK_SEC_PART_BIT, PTE_MARK(%rbx);				\
  CHECK_RESTART (name)

#define TST_MARK_COMPLETE_START(name) \
  ERI_GLOBAL_HIDDEN (ERI_TST_LIVE_COMPLETE_START_SYMBOL (name))

/* If not TST, it's not required as tf is already cleared in new_rflags,
   so when tst_skip_ctf is 0.
*/
#ifndef ERI_NON_TST
# define TST_NEW_RFLAGS_CTF(reg_or_mem) \
  cmpq	$0, PTE_TST_SKIP_CTF(%rbx);					\
  je	1f;								\
  andq	$~ERI_TRACE_FLAG_MASK, reg_or_mem;				\
1:
#else
# define TST_NEW_RFLAGS_CTF(reg_or_mem)
#endif

/* Fix tf:
   rflags = (rflags & TF_MASK) | new_rflags

   Setting rflags has to be like this. We can't move rflags out of stack
   as by so clear tf code in lresume may not work.  */
#define SAVE_NEW_RFLAGS_FROM_REG(reg) \
  andq	$ERI_TRACE_FLAG_MASK, STACK_RFLAGS(%rsp);			\
  TST_NEW_RFLAGS_CTF (reg)						\
  orq	reg, STACK_RFLAGS(%rsp)

/* %rsp should be top - ERI_LIVE_ENTRY_SAVED_REG_SIZE16.  */
#define SAVE_NEW_RFLAGS(reg) \
  pushfq;								\
  popq	reg;								\
  SAVE_NEW_RFLAGS_FROM_REG (reg)

/* Destory %rax.
   We have to atomically set dir to cont if no signal yet, because signal
   can happen between any two instructions. Using atomic cmpxchg means we
   have to clear dir when we return. There are three possible ways return:
   1, no signal, dir is cleared in cont, 2, signal before setting mark to
   0, dir is cleared in resume_ret, 3, signal after, dir is cleared in fix.
*/
#define CHECK_SET_DIR(cont, reg) \
  xorq	%rax, %rax;							\
  movq	PASTE2 (TE_THREAD_, cont, _CONT)(%rbx), reg;			\
  cmpxchgq	reg, PTE_DIR(%rbx)

#define EXTERNAL_RET_DIR(reg) \
  CHECK_SET_DIR (EXTERNAL, reg);					\
									\
  RESTORE_EXTERNAL_RET;							\
  jmp	*TE_THREAD_RET(%rbx)

#define INTERNAL_RET_DIR(reg) \
  CHECK_SET_DIR (INTERNAL, reg);					\
									\
  RESTORE_INTERNAL_RET;							\
  jmp	*PTE_DIR(%rbx)

#define ENTER_RESTART(reg) \
  MOV_MM (PTE_START(%rbx), PTE_CONT(%rbx), reg);			\
  movq	$0, TE_RESTART(%rbx)

#define RESTART_RESUME_RET \
  ENTER_RESTART (%rax);							\
									\
  RESTORE_INTERNAL_RET;							\
  jmp	*TE_RESUME_RET(%rbx)

#define TH_CALL(reg, fn) \
  movq	TE_THREAD(%rbx), reg;						\
  call	fn

/************************************************/
/* eri_live_entry: syscall			*/
/************************************************/

#define SYSCALL_RAX		ERI_LIVE_ENTRY_SYSCALL_INFO_RAX
#define SYSCALL_R11		ERI_LIVE_ENTRY_SYSCALL_INFO_R11
#define SYSCALL_RFLAGS		ERI_LIVE_ENTRY_SYSCALL_INFO_RFLAGS

#define SYSCALL_TST_CLONE_TF	ERI_LIVE_ENTRY_SYSCALL_INFO_TST_CLONE_TF

#define SYSCALL_SIZE16		ERI_LIVE_ENTRY_SYSCALL_INFO_SIZE16

.lsyscall:
  movq	%r10, %rcx

  /* For rflags w/o tf.  */
  movq	-8(%rsp), %r11

  movq	$0, TE_SYSCALL_NEW_THREAD(%rbx)

  cmpl	$__NR_clone, %eax
  jne	.lsyscall_no_extra_save

  movq	%rbp, TE_EXT_RBP(%rbx)
  movq	%r12, TE_EXT_R12(%rbx)
  movq	%r13, TE_EXT_R13(%rbx)
  movq	%r14, TE_EXT_R14(%rbx)
  movq	%r15, TE_EXT_R15(%rbx)

.lsyscall_no_extra_save:
  subq	$SYSCALL_SIZE16, %rsp
  movq	%rax, SYSCALL_RAX(%rsp)
  movq	%r11, SYSCALL_RFLAGS(%rsp)
#ifndef ERI_NON_TST
  movq	$0, SYSCALL_TST_CLONE_TF(%rsp)
#endif

  movq	%rsp, %rax
  pushq	%rbx
  pushq	%rax

  call	eri_live_syscall
  addq	$16, %rsp
  testb	%al, %al
  jz	.lrestart_syscall
  /* Essentially 1: jmp	1b; to hold the thread state (waiting for e.g.
     the incoming signal).
  */
  jl	.lhold_syscall

  movq	%rsp, %rax
  addq	$SYSCALL_SIZE16, %rsp

  MOV_MM (SYSCALL_RAX(%rax), STACK_RAX(%rsp), %r11)
  MOV_MM (SYSCALL_R11(%rax), STACK_R11(%rsp), %r11)
  movq	SYSCALL_RFLAGS(%rax), %r11
  SAVE_NEW_RFLAGS_FROM_REG (%r11)

  /* Reset tf for %r11: r11 = (rflags & TF_MASK) | r11  */
  movq	STACK_RFLAGS(%rsp), %r11
  andq	$ERI_TRACE_FLAG_MASK, %r11
  TST_NEW_RFLAGS_CTF (STACK_R11(%rsp))
  orq	%r11, STACK_R11(%rsp)

  MOV_MM (PTE_CONT(%rbx), STACK_RCX(%rsp), %r11)
  jmp	.ldone_syscall

.lhold_syscall:
  SET_COMPLETE_RESTART_START (hold_syscall, %rax)
  MARK_SEC_PART_AND_CHECK_RESTART (hold_syscall)
COMPLETE_START_LABEL (hold_syscall):
TST_MARK_COMPLETE_START (hold_syscall)

  MOV_MM (PTE_START(%rbx), PTE_CONT(%rbx), %rax)

  addq	$SYSCALL_SIZE16, %rsp

  movl	$__NR_sched_yield, %eax
  syscall

.ldone_syscall:
  INTERNAL_RET_DIR (%r11)

.lrestart_syscall:
RESTART_START_LABEL (hold_syscall):
  addq	$SYSCALL_SIZE16, %rsp

  RESTART_RESUME_RET

/************************************************/
/* eri_live_entry: sync_async			*/
/************************************************/

.lsync_async:
  SET_RESTART_START (sync_async, %rax)
  movq	$0, TE_SYNC_REPEAT_TRACE(%rbx)

  movq	%rcx, %rdi
  TH_CALL (%rsi, eri_live_sync_async)

  RESTORE_GENERAL_REGS

  movq	$0, PTE_MARK(%rbx)
  /* Check restart modifies rflags.  */
  CHECK_RESTART (sync_async)

  RESTORE_RFLAGS
.lsync_async1:
  xchgq	TE_RSP(%rbx), %rsp
.lsync_async2:
  jmp	*TE_THREAD_RET(%rbx)

RESTART_START_LABEL (sync_async):
  /* Not fixing if %rdi is not set to the interrupted rip.  */
  cmpq	$0, TE_FIX_RESTART(%rbx)
  je	.lsync_async_restart_restore

  movq	%rax, TE_FIX_RESTART_RAX(%rbx)

  CMP_MM (PTE_RET(%rbx), TE_FIX_RESTART_RIP(%rbx), %rax)
  je	.lsync_async_restart_restore_inst

#define SYNC_JMP_IF_BELOW(label, dst) \
  leaq	label(%rip), %rax;						\
  cmpq	%rax, TE_FIX_RESTART_RIP(%rbx);					\
  jb	dst

  SYNC_JMP_IF_BELOW (.lsync_async1, .lsync_async_restart_restore1)
  SYNC_JMP_IF_BELOW (.lsync_async2, .lsync_async_restart_restore2)
  jmp	.lsync_async_restart_restore3

.lsync_async_restart_restore_inst:
  MOV_MM (TE_FIX_RESTART_RBX(%rbx), PTE_RBX(%rbx), %rax)
.lsync_async_restart_restore3:
  xchgq	%rsp, TE_RSP(%rbx)
.lsync_async_restart_restore2:
  pushq	TE_FIX_RESTART_RFLAGS(%rbx)
.lsync_async_restart_restore1:
  movq	TE_FIX_RESTART_RAX(%rbx), %rax
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
  TH_CALL (%rsi, eri_live_restart_sync_async)

  /* Not RESTORE_INTERNAL_RET as mark is already zeroed.  */
  RESTORE_EXTERNAL_RET
  jmp	*TE_RESUME_RET(%rbx)

/************************************************/
/* eri_live_entry: atomic common		*/
/************************************************/

#define ATOMIC_SIZE_LABEL(sz, name)	ATOMIC_LABEL (PASTE (name, sz))

#define ATOMIC_NAME		ERI_LIVE_ATOMIC_NAME

#define AT_REG_MEM_TABLE	%r11
#define AT_REG_IDX		%rax
#define AT_REG_LOCK_LP_CNT	%rcx
#define AT_REG_MEM		%rdi
#define AT_REG_VER		%rsi
#define AT_REG_VAL		%r8
#define AT_REG_VAL_SZ		%ERI_R8
#define AT_REG_LD_RES		%rdx
#define AT_REG_LD_RES_SZ	%ERI_RDX

#define AT_LOAD_VAL		movq	PTE_VAR0(%rbx), AT_REG_VAL
#define AT_LOAD_MEM		movq	PTE_VAR1(%rbx), AT_REG_MEM

#define AT_LOAD_MEM_TABLE \
  movq	eri_live_entry_atomic_mem_table(%rip), AT_REG_MEM_TABLE

#define AT_HASH_MEM \
  AT_LOAD_MEM;								\
  TH_CALL (%rsi, eri_live_atomic_hash_mem)

#define AT_MEM(idx)		(AT_REG_MEM_TABLE, idx, 8)

#define AT_LOCK(idx) \
  AT_LOAD_MEM_TABLE;							\
  movq	$16, AT_REG_LOCK_LP_CNT;					\
1:									\
  lock btsq	$0, AT_MEM (idx);					\
  jnc	2f;								\
  loop	1b;								\
									\
  pushq	%rax;								\
  movl	$__NR_sched_yield, %eax;					\
  syscall;								\
  popq	%rax;								\
  AT_LOAD_MEM_TABLE;							\
  movq	$16, AT_REG_LOCK_LP_CNT;					\
  jmp	1b;								\
									\
2:

#define AT_LOCK_LOAD		AT_LOCK

#define AT_LOCK_STORE(idx) \
  movq	$2, AT_REG_VER;							\
  AT_LOCK (idx)

#define AT_UNLOCK(idx) \
  lock andb	$-2, AT_MEM (idx)

#define AT_UNLOCK_LOAD(idx) \
  movq	AT_MEM (idx), AT_REG_VER;					\
  AT_UNLOCK (idx);							\
  shrq	$1, AT_REG_VER

#define AT_UNLOCK_STORE(idx) \
  xaddq	AT_REG_VER, AT_MEM (idx);					\
  AT_UNLOCK (idx);							\
  shrq	$1, AT_REG_VER

#define TST_MARK_ATOMIC_COMPLETE_START(sz, name) \
  TST_MARK_COMPLETE_START (ATOMIC_NAME (sz, name))

/************************************************/
/* eri_live_entry: atomic_load			*/
/************************************************/

#define ATOMIC_LOAD(sz) \
ATOMIC_SIZE_LABEL (sz, load):						\
  SET_COMPLETE_RESTART_START (ATOMIC_NAME (sz, load), %rax);		\
									\
  AT_HASH_MEM;								\
  AT_LOAD_MEM;								\
									\
  AT_LOCK_LOAD (AT_REG_IDX);						\
									\
  MARK_SEC_PART_AND_CHECK_RESTART (ATOMIC_NAME (sz, load));		\
									\
  PASTE (mov, sz)	(AT_REG_MEM), AT_REG_LD_RES_SZ (sz);		\
COMPLETE_START_LABEL (ATOMIC_NAME (sz, load)):				\
  TST_MARK_ATOMIC_COMPLETE_START (sz, load)				\
									\
  AT_UNLOCK_LOAD (AT_REG_IDX);						\
  movq	AT_REG_LD_RES, PTE_VAR0(%rbx);					\
  TH_CALL (%rcx, eri_live_atomic_load);					\
									\
  EXTERNAL_RET_DIR (%rdi);						\
									\
RESTART_START_LABEL (ATOMIC_NAME (sz, load)):				\
  AT_UNLOCK (AT_REG_IDX);						\
  RESTART_RESUME_RET

/************************************************/
/* eri_live_entry: atomic_store			*/
/************************************************/

#define ATOMIC_STORE(sz) \
ATOMIC_SIZE_LABEL (sz, store):						\
  SET_COMPLETE_RESTART_START (ATOMIC_NAME (sz, store), %rax);		\
									\
  AT_HASH_MEM;								\
  AT_LOAD_VAL;								\
  AT_LOAD_MEM;								\
									\
  AT_LOCK_STORE (AT_REG_IDX);						\
									\
  MARK_SEC_PART_AND_CHECK_RESTART (ATOMIC_NAME (sz, store));		\
									\
  PASTE (mov, sz)	AT_REG_VAL_SZ (sz), (AT_REG_MEM);		\
COMPLETE_START_LABEL (ATOMIC_NAME (sz, store)):				\
  TST_MARK_ATOMIC_COMPLETE_START (sz, store)				\
									\
  AT_UNLOCK_STORE (AT_REG_IDX);						\
  TH_CALL (%rdx, eri_live_atomic_store);				\
									\
  INTERNAL_RET_DIR (%rdi);						\
									\
RESTART_START_LABEL (ATOMIC_NAME (sz, store)):				\
  AT_UNLOCK (AT_REG_IDX);						\
  RESTART_RESUME_RET

/************************************************/
/* eri_live_entry: atomic_inc / atomic_dec	*/
/************************************************/

#define ATOMIC_INC_DEC(sz, op) \
ATOMIC_SIZE_LABEL (sz, op):						\
  SET_COMPLETE_RESTART_START (ATOMIC_NAME (sz, op), %rax);		\
									\
  /* For rflags w/o tf.  */						\
  subq	$16, %rsp;							\
  AT_HASH_MEM;								\
  AT_LOAD_MEM;								\
									\
  addq	$8, %rsp;							\
  AT_LOCK_STORE (AT_REG_IDX);						\
									\
  MARK_SEC_PART_AND_CHECK_RESTART (ATOMIC_NAME (sz, op));		\
									\
  popfq;								\
  PASTE (mov, sz)	(AT_REG_MEM), AT_REG_LD_RES_SZ (sz);		\
  PASTE (op, sz)	(AT_REG_MEM);					\
COMPLETE_START_LABEL (ATOMIC_NAME (sz, op)):				\
  TST_MARK_ATOMIC_COMPLETE_START (sz, op)				\
  SAVE_NEW_RFLAGS (%rcx);						\
									\
  AT_UNLOCK_STORE (AT_REG_IDX);						\
  TH_CALL (%rcx, eri_live_atomic_load_store);				\
									\
  INTERNAL_RET_DIR (%rdi);						\
									\
RESTART_START_LABEL (ATOMIC_NAME (sz, op)):				\
  movq	TE_TOP_SAVED(%rbx), %rsp;					\
  AT_UNLOCK (AT_REG_IDX);						\
  RESTART_RESUME_RET

#define ATOMIC_INC(sz)		ATOMIC_INC_DEC (sz, inc)
#define ATOMIC_DEC(sz)		ATOMIC_INC_DEC (sz, dec)

/************************************************/
/* eri_live_entry: atomic_xchg			*/
/************************************************/

#define ATOMIC_XCHG(sz) \
ATOMIC_SIZE_LABEL (sz, xchg):						\
  SET_COMPLETE_RESTART_START (ATOMIC_NAME (sz, xchg), %rax);		\
									\
  AT_HASH_MEM;								\
  AT_LOAD_VAL;								\
  AT_LOAD_MEM;								\
									\
  AT_LOCK_STORE (AT_REG_IDX);						\
									\
  MARK_SEC_PART_AND_CHECK_RESTART (ATOMIC_NAME (sz, xchg));		\
									\
  PASTE (xchg, sz)	AT_REG_VAL_SZ (sz), (AT_REG_MEM);		\
COMPLETE_START_LABEL (ATOMIC_NAME (sz, xchg)):				\
  TST_MARK_ATOMIC_COMPLETE_START (sz, xchg)				\
									\
  AT_UNLOCK_STORE (AT_REG_IDX);						\
  movq	AT_REG_VAL, PTE_VAR0(%rbx);					\
  movq	AT_REG_VAL, AT_REG_LD_RES;					\
  TH_CALL (%rcx, eri_live_atomic_load_store);				\
									\
  EXTERNAL_RET_DIR (%rdi);						\
									\
RESTART_START_LABEL (ATOMIC_NAME (sz, xchg)):				\
  AT_UNLOCK (AT_REG_IDX);						\
  RESTART_RESUME_RET

/************************************************/
/* eri_live_entry: atomic_cmpxchg		*/
/************************************************/

#define ATOMIC_CMPXCHG(sz) \
ATOMIC_SIZE_LABEL (sz, cmpxchg):					\
  SET_COMPLETE_RESTART_START (ATOMIC_NAME (sz, cmpxchg), %rax);	\
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
  AT_LOCK_STORE (%r10);							\
									\
  MARK_SEC_PART_AND_CHECK_RESTART (ATOMIC_NAME (sz, cmpxchg));		\
									\
  popfq;								\
  PASTE (mov, sz)	(AT_REG_MEM), AT_REG_LD_RES_SZ (sz);		\
  PASTE (cmpxchg, sz)	AT_REG_VAL_SZ (sz), (AT_REG_MEM);		\
COMPLETE_START_LABEL (ATOMIC_NAME (sz, cmpxchg)):			\
  TST_MARK_ATOMIC_COMPLETE_START (sz, cmpxchg)				\
  SAVE_NEW_RFLAGS (%rcx);						\
									\
  AT_UNLOCK_STORE (%r10);						\
  movq	%rax, STACK_RAX(%rsp);						\
  TH_CALL (%rcx, eri_live_atomic_load_store);				\
									\
  INTERNAL_RET_DIR (%rdi);						\
									\
RESTART_START_LABEL (ATOMIC_NAME (sz, cmpxchg)):			\
  movq	TE_TOP_SAVED(%rbx), %rsp;					\
  AT_UNLOCK (%r10);							\
  RESTART_RESUME_RET

/************************************************/
/* eri_live_entry: atomic			*/
/************************************************/

#define IF_ATOMIC_SIZE(sz, name) \
  cmpq	$_ERS_ATOMIC_SIZE (sz), %r11;					\
  je	ATOMIC_SIZE_LABEL (sz, name)

 #define ATOMIC_OP(op) \
  PASTE (ATOMIC_, op) (b);						\
  PASTE (ATOMIC_, op) (w);						\
  PASTE (ATOMIC_, op) (l);						\
  PASTE (ATOMIC_, op) (q)

#define ATOMIC(op, name) \
ATOMIC_LABEL (name):							\
  LOAD_OP_RFLAGS (%r11);						\
  IF_ATOMIC_SIZE (b, name);						\
  IF_ATOMIC_SIZE (w, name);						\
  IF_ATOMIC_SIZE (l, name);						\
  IF_ATOMIC_SIZE (q, name);						\
  jmp	.lerror;							\
									\
  ATOMIC_OP (op)

  ATOMIC (LOAD, load)
  ATOMIC (STORE, store)
  ATOMIC (INC, inc)
  ATOMIC (DEC, dec)
  ATOMIC (XCHG, xchg)
  ATOMIC (CMPXCHG, cmpxchg)

  .size eri_live_entry, . - eri_live_entry

/************************************************/
/* eri_live_entry_do_syscall			*/
/************************************************/

#define ARG_INFO		16
#define ARG_ENTRY		24

ERI_GLOBAL_HIDDEN_FUNCTION (eri_live_entry_do_syscall)
  pushq	%rbx
  movq	ARG_ENTRY(%rsp), %rbx
  movq	$0, TE_COMPLETE_START(%rbx)
  SET_RESTART_START (do_syscall, %r11)

  movq	%rcx, %r10
  movq	ARG_INFO(%rsp), %r11
  movq	SYSCALL_RAX(%r11), %rax
  movq	%rsp, TE_SYSCALL_RSP(%rbx)
  pushq	SYSCALL_RFLAGS(%r11)
  MARK_SEC_PART_AND_CHECK_RESTART (do_syscall)

  popfq
  syscall
COMPLETE_START_LABEL (do_syscall):
TST_MARK_COMPLETE_START (do_syscall)

  movq	ARG_INFO(%rsp), %rcx
  movq	%rax, SYSCALL_RAX(%rcx)
  movq	%r11, SYSCALL_R11(%rcx)
  pushfq
  popq	SYSCALL_RFLAGS(%rcx)

  popq	%rbx
  movb	$1, %al
  ret

RESTART_START_LABEL (do_syscall):
  movq	TE_SYSCALL_RSP(%rbx), %rsp

  popq	%rbx
  movb	$0, %al
  ret

  .size eri_live_entry_do_syscall, . - eri_live_entry_do_syscall

/************************************************/
/* eri_live_entry_do_clone			*/
/************************************************/

#define CLONE_FLAGS		ERI_LIVE_ENTRY_CLONE_INFO_FLAGS
#define CLONE_CHILD_STACK	ERI_LIVE_ENTRY_CLONE_INFO_CHILD_STACK
#define CLONE_PTID		ERI_LIVE_ENTRY_CLONE_INFO_PTID
#define CLONE_CTID		ERI_LIVE_ENTRY_CLONE_INFO_CTID
#define CLONE_NEWTLS		ERI_LIVE_ENTRY_CLONE_INFO_NEWTLS

ERI_GLOBAL_HIDDEN_FUNCTION (eri_live_entry_do_clone)

  /* Stack for the child:
		top ---
		    rflags/rax/rdi/rsi... (SAVED_REG_SIZE16)
	  top_saved ---
		    eri_syscall_info (SYSCALL_SIZE16)
		    eri_syscall args (16)
	eri_syscall ---		after start:	eri_syscall ---
		    ret					    ret
		    padding (8)				    padding (8)
		    sig_mask (ERI_SIGMASK_SIZE16)	    sig_mask
		    padding (8)			  eri_start ---
		    info
     eri_do_syscall ---
		    .lchild_return
		    rbx, child_entry
	    syscall --- CLONE_CHILD_STACK

     eri_syscall_info:	eri_live_entry_syscall_info
     eri_syscall:	eri_live_syscall
     eri_start:		eri_live_start_thread
     sig_mask:		eri_sigmask
     info:		eri_live_entry_syscall_info *
     eri_do_syscall:	eri_live_entry_do_syscall
  */

  movq	CLONE_CHILD_STACK(%rdx), %rax
  leaq	.lchild_return(%rip), %r11
  movq	%r11, 8(%rax)

  pushq	%rsi

  pushq	%rdi
  pushq	%rcx
  movq	CLONE_FLAGS(%rdx), %rdi
  movq	%rax, %rsi
  movq	CLONE_CTID(%rdx), %rcx
  movq	CLONE_NEWTLS(%rdx), %r8
  movq	CLONE_PTID(%rdx), %rdx

  call	eri_live_entry_do_syscall
  addq	$16, %rsp

  popq	%rsi
  cmpb	$1, ERI_SIGMASK_MASK_ALL(%rsi)
  je	.lfast_do_clone_return
  movb	%al, %r8b

  CHECK_RESTORE_SIG_MASK (leaq	ERI_SIGMASK_MASK(%rsi), %rsi;)

#ifndef ERI_NON_TST
# define TST_RESTORE_CLONE_TF \
  /* Set by sigaction from the test.  */				\
  movq	-16(%rsp), %rax;						\
  movq	SYSCALL_TST_CLONE_TF(%rax), %r11;				\
  testq	%r11, %r11;							\
  jz	1f;								\
  pushfq;								\
  orq	%r11, (%rsp);							\
  popfq;								\
  orq	%r11, SYSCALL_R11(%rax);					\
1:
#else
# define TST_RESTORE_CLONE_TF
#endif

  TST_RESTORE_CLONE_TF

  movb	%r8b, %al
.lfast_do_clone_return:
  ret

.lchild_return:
  movq	TE_EXT_RBP(%rbx), %rbp
  movq	TE_EXT_R12(%rbx), %r12
  movq	TE_EXT_R13(%rbx), %r13
  movq	TE_EXT_R14(%rbx), %r14
  movq	TE_EXT_R15(%rbx), %r15

  INSTALL_ENTRY

  SIGALTSTACK_NO_RESTORE

  addq	$ERI_STACK_SIZE16 + 16, %rsp
  movq	TE_THREAD(%rbx), %rdi
  call	eri_live_start_thread	
  cmpb	$1, ERI_SIGMASK_MASK_ALL(%rsp)
  je	.lfast_child_return

  CHECK_RESTORE_SIG_MASK (leaq	ERI_SIGMASK_MASK(%rsp), %rsi;)

  TST_RESTORE_CLONE_TF

.lfast_child_return:
  addq	$ERI_SIGMASK_SIZE16 + 8, %rsp

  movb	$1, %al
  ret

  .size eri_live_entry_do_clone, . - eri_live_entry_do_clone
