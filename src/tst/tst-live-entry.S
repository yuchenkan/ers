#include "tst/tst-live-entry.h"

#include "public/impl.h"

#include <asm/unistd.h>

#define SUFFIX_LABEL(i)		SUFFIX (LABEL (i))
#define GLOBAL_SUFFIX(label)	.global SUFFIX (label);

#define PROCESS \
  LABELS (GLOBAL_SUFFIX)	\
				\
  movq	$1, %rax;		\
  movq	xchg_mem_b, %rcx;	\
  movq	xchg_mem_w, %rdx;	\
  movq	xchg_mem_l, %rbx;	\
  movq	inc_mem, %rdi;		\
  movq	$6, %rsi;		\
  movq	$7, %r8;		\
  movq	$8, %r9;		\
  movq	$9, %r10;		\
  movq	xchg_mem_q, %r11;	\
  pushfq;			\
  movq	$0x150, (%rsp);		\
  popfq;			\
  nop;				\
SUFFIX_LABEL (INOP):		\
  XCHG (b, %al, (%rcx));	\
SUFFIX_LABEL (IXCHGB):		\
  XCHG (w, %ax, (%rdx));	\
SUFFIX_LABEL (IXCHGW):		\
  XCHG (l, %eax, (%rbx));	\
SUFFIX_LABEL (IXCHGL):		\
  XCHG (q, %rax, (%r11));	\
SUFFIX_LABEL (IXCHGQ):		\
  INC (b, (%rdi));		\
SUFFIX_LABEL (IINCB):		\
  INC (w, (%rdi));		\
SUFFIX_LABEL (IINCW):		\
  INC (l, (%rdi));		\
SUFFIX_LABEL (IINCL):		\
  INC (q, (%rdi));		\
SUFFIX_LABEL (IINCQ):		\
  movl	$__NR_getpid, %eax;	\
SUFFIX_LABEL (ISNR):		\
  SYSCALL;			\
SUFFIX_LABEL (ISYS):		\
  movq	jmp_mem, %rcx;		\
SUFFIX_LABEL (IMJMP):		\
  SYNC (jmp	*%rcx;)		\
  nop;				\
SUFFIX_LABEL (IJMP):		\
  pushfq;			\
SUFFIX_LABEL (IPUFQ):		\
  movq	$0, (%rsp);		\
SUFFIX_LABEL (ISTF):		\
  popfq;			\
SUFFIX_LABEL (IPOFQ):		\
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

#define RAW_XCHG(sz, reg, mem)	_ERS_PASTE (xchg, sz)	reg, mem
#define RAW_INC(sz, mem)	_ERS_PASTE (inc, sz)	mem
#define RAW_SYSCALL		syscall
#define RAW_SYNC(inst)		inst

#define XCHG			RAW_XCHG
#define INC			RAW_INC
#define SYSCALL			RAW_SYSCALL
#define SYNC			RAW_SYNC

#define SUF			_raw
  PROCESS
  call	process
1:

#undef XCHG
#undef INC
#undef SYSCALL
#undef SYNC
#undef SUF

#ifdef TST_XCHG
# define XCHG(sz, reg, mem)	_ERS_ATOMIC_XCHG (sz, reg, mem)
#else
# define XCHG			RAW_XCHG
#endif

#ifdef TST_INC
# define INC(sz, mem)		_ERS_ATOMIC_INC (sz, mem)
#else
# define INC			RAW_INC
#endif

#ifdef TST_SYSCALL
# define SYSCALL		_ERS_SYSCALL
#else
# define SYSCALL		RAW_SYSCALL
#endif

#ifdef TST_SYNC
# define SYNC			_ERS_SYNC_ASYNC
#else
# define SYNC			RAW_SYNC
#endif

#define SUF

  PROCESS

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
