/* vim: set ft=gas: */

#include <live-signal-thread-local.h>

#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/syscall-offsets.h>

#include <live-signal-thread-local-offsets.h>
#include <lib/syscall-offsets.h>

  .text

ERI_FUNCTION (sig_handler)
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
  movq	%rsp, %rdi
  subq	$8, %rsp
  .cfi_adjust_cfa_offset 8
  call	sig_handler_frame
  addq	$8, %rsp
  .cfi_adjust_cfa_offset -8
  ret
  .cfi_endproc
  ERI_END_FUNCTION (sig_handler)

ERI_FUNCTION (eri_live_signal_thread_init_main)
  subq	$8, %rsp
  call	init_group

  leaq	SIGNAL_THREAD_STACK(%eax), %rsp
  addq	$SIGNAL_THREAD_STACK_SIZE, %rsp

  movq	%rax, %rdi
  call	start_group
  ERI_ASSERT_FALSE
  ERI_END_FUNCTION (eri_live_signal_thread_init_main)

#define EVENT_SIG_RESTART	SIGNAL_THREAD_EVENT_SIG_RESTART
#define EVENT_SIG_RESET_RESTART	SIGNAL_THREAD_EVENT_SIG_RESET_RESTART

#define RESTART(reset, restart, sig_th, tmp) \
  ERI_MOV_LM (reset, EVENT_SIG_RESET_RESTART(sig_th), tmp);		\
  ERI_MOV_LM (restart, EVENT_SIG_RESTART(sig_th), tmp);			\
restart:

#define RESTART_RETURN(sig_th) \
  movq	$0, EVENT_SIG_RESTART(sig_th);					\
  movb	$0, %al;							\
  ret

#define DONE_RETURN \
  movb	$1, %al;							\
  ret

#define RESET_RESTART(reset, sig_th) \
reset:									\
  movq	$0, EVENT_SIG_RESTART(sig_th)

ERI_FUNCTION (sig_mask_async)

  movq	%rdi, %r8

  movq	(%rsi), %rax
RESTART (.lsig_mask_reset_restart, .lsig_mask_restart, %r8, %r11)
  cmpq	$0, SIGNAL_THREAD_SIG_INFO(%r8)
  jz	.lsig_mask_syscall
  movq	SIGNAL_THREAD_SIG_INFO(%r8), %r11
  /* XXX: SIGRTMAX <= 64 */
  movq	ERI_SIGINFO_SIG(%r11), %r11
  decq	%r11
  btq	%r11, %rax
  jnc	.lsig_mask_syscall

  RESTART_RETURN (%r8)

.lsig_mask_syscall:
  movl	$__NR_rt_sigprocmask, %eax
  movq	$ERI_SIG_SETMASK, %rdi
  xorq	%rdx, %rdx
  movq	$ERI_SIG_SETSIZE, %r10
  syscall
RESET_RESTART (.lsig_mask_reset_restart, %r8)
  testq	%rax, %rax
  jnz	.lsig_mask_error

  DONE_RETURN

.lsig_mask_error:
  ERI_ASSERT_FALSE

  ERI_END_FUNCTION (sig_mask_async)
