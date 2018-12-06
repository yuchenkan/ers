#include "tst-live-entry.h"

#include "public/impl.h"

#include <asm/unistd.h>

#define TL(l)	_ERS_PASTE (T, l)
#define TLL(i)	TL (L (i))
#define GTL(l)	.global TL (l);

#define TP \
  LS (GTL)			\
				\
  movq	$0, %rax;		\
  movq	vvv, %rcx;		\
  movq	$3, %rdx;		\
  movq	$4, %rdi;		\
  movq	$5, %rsi;		\
  movq	$7, %r8;		\
  movq	$8, %r9;		\
  movq	$9, %r10;		\
  movq	$10, %r11;		\
  pushfq;			\
  movq	$0x150, (%rsp);		\
  popfq;			\
  nop;				\
TLL (INOP):			\
  _ERS_PASTE (XCHG, T) (%rax, (%rcx));	\
TLL (IXCHG):			\
  movl	$__NR_getpid, %eax;	\
TLL (ISNR):			\
  _ERS_PASTE (SYSCALL, T);	\
TLL (ISYS):			\
  movq	uuu, %rcx;		\
TLL (IMJMP):			\
  _ERS_PASTE (SYNC, T) (jmp	*%rcx;)	\
  nop;				\
TLL (IJMP):			\
  pushfq;			\
TLL (IPUFQ):			\
  movq	$0, (%rsp);		\
TLL (ISTF):			\
  popfq;			\
TLL (IPOFQ):			\
  nop

  .text

  .align 16
  .type main, @function
  .global main
main:
  call	setup
  movq	$1, %rbx
  movq	$6, %rbp
  movq	$11, %r12
  movq	$12, %r13
  movq	$13, %r14
  movq	$14, %r15

#define XCHGr(a, b)	xchg	a, b
#define SYSCALLr	syscall
#define SYNCr(i)	i
#define T		r
  TP;
  call	process
1:

#ifdef TT_XCHG
# define XCHGx(a, b)	_ERS_XCHG (a, b)
#else
# define XCHGx(a, b)	XCHGr (a, b)
#endif

#ifdef TT_SYSCALL
# define SYSCALLx	_ERS_SYSCALL
#else
# define SYSCALLx	SYSCALLr
#endif

#ifdef TT_SYNC
# define SYNCx(i)	_ERS_SYNC (i)
#else
# define SYNCx(i)	SYNCr (i)
#endif

#undef T
#define T		x
  TP;
  call	process
  testb	%al, %al
  jnz	1b
  movl	$__NR_exit, %eax
  xorq	%rdi, %rdi
  syscall
  .size main, . - main

  .align 16
  .type sig_x_sig_step, @function
  .global sig_x_sig_step
sig_x_sig_step:
  subq	$8, %rsp
  pushq	%rsi
  pushq	%rdx
  call	sig_sig_step
  popq	%rdx
  popq	%rsi
  addq	$8, %rsp

  testq	%rax, %rax
  jz	.lignore

  movl	%eax, %edi
  jmp	eri_live_sigaction

.lignore:
  ret
  .size sig_x_sig_step, . - sig_x_sig_step
