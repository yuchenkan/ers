/* vim: set ft=gas: */

#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/syscall-offsets.h>

#include <live/signal-thread-local.h>
#include <live/signal-thread-local-offsets.h>

  .text

ERI_FUNCTION (sig_handler)
  movq	%rsp, %rdi
  jmp	sig_handler_frame
  ERI_END_FUNCTION (sig_handler)

ERI_FUNCTION (eri_live_signal_thread__init_main)
  subq	$8, %rsp
  call	init_group

  leaq	SIGNAL_THREAD_STACK(%eax), %rsp
  addq	$SIGNAL_THREAD_STACK_SIZE, %rsp

  movq	%rax, %rdi
  call	start_group
  ERI_ASSERT_FALSE
  ERI_END_FUNCTION (eri_live_signal_thread__init_main)

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
