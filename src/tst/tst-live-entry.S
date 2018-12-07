/* vim: set ft=gas: */

#include "tst/tst-live-entry.h"

#include "public/impl.h"

#include <asm/unistd.h>

#define SUFFIX_LABEL(i)		SUFFIX (LABEL (i))
#define GLOBAL_SUFFIX(label)	.global SUFFIX (label);

#define PERS_LOAD_CMP(sz, res, reg) \
  _ERS_PASTE (cmp, sz)	reg, res

#define PERS_ATOMIC_CMP(sz, reg, mem) \
  _ERS_ATOMIC_COMM_LOAD (sz, mem, PERS_LOAD_CMP, reg)

#define PROCESS \
  LABELS (GLOBAL_SUFFIX)	\
				\
  movq	$1, %rax;		\
  movq	xchg_mem_b, %rcx;	\
  movq	xchg_mem_w, %rdx;	\
  movq	xchg_mem_l, %rbx;	\
  movq	inc_mem, %rdi;		\
  movq	stor_mem, %rsi;		\
  movq	load_mem, %r8;		\
  movq	cmpxchg_mem, %r9;	\
  movq	cmp_mem, %r10;		\
  movq	xchg_mem_q, %r11;	\
				\
  pushfq;			\
  movq	$0x150, (%rsp);		\
  popfq;			\
				\
  nop;				\
				\
SUFFIX_LABEL (INOP):		\
  PXCHG (b, %al, (%rcx));	\
SUFFIX_LABEL (IXCHGB):		\
  PXCHG (w, %ax, (%rdx));	\
SUFFIX_LABEL (IXCHGW):		\
  PXCHG (l, %eax, (%rbx));	\
SUFFIX_LABEL (IXCHGL):		\
  PXCHG (q, %rax, (%r11));	\
				\
SUFFIX_LABEL (IXCHGQ):		\
  PINC (b, (%rdi));		\
SUFFIX_LABEL (IINCB):		\
  PINC (w, (%rdi));		\
SUFFIX_LABEL (IINCW):		\
  PINC (l, (%rdi));		\
SUFFIX_LABEL (IINCL):		\
  PINC (q, (%rdi));		\
SUFFIX_LABEL (IINCQ):		\
				\
  movq	$0xf00000000, %rax;	\
SUFFIX_LABEL (IMSTORQ):		\
  PSTOR (q, %rax, (%rsi));	\
SUFFIX_LABEL (ISTORQ):		\
  movq	(%rsi), %rax;		\
SUFFIX_LABEL (ILSTORQ):		\
				\
  movl	$0xf0000, %eax;		\
SUFFIX_LABEL (IMSTORL):		\
  PSTOR (l, %eax, (%rsi));	\
SUFFIX_LABEL (ISTORL):		\
  movq	(%rsi), %rax;		\
SUFFIX_LABEL (ILSTORL):		\
				\
  movw	$0xf00, %ax;		\
SUFFIX_LABEL (IMSTORW):		\
  PSTOR (w, %ax, (%rsi));	\
SUFFIX_LABEL (ISTORW):		\
  movq	(%rsi), %rax;		\
SUFFIX_LABEL (ILSTORW):		\
				\
  movb	$0xf, %al;		\
SUFFIX_LABEL (IMSTORB):		\
  PSTOR (b, %al, (%rsi));	\
SUFFIX_LABEL (ISTORB):		\
  movq	(%rsi), %rax;		\
SUFFIX_LABEL (ILSTORB):		\
				\
  PLOAD (q, (%r8), %rbx);	\
SUFFIX_LABEL (ILOADQ):		\
				\
  movq	$0, %rax;		\
SUFFIX_LABEL (IMCMPXCHGQ1):	\
  movq	$1, %rbx;		\
SUFFIX_LABEL (IMCMPXCHGQ2):	\
  PCMPXCHG (q, %rbx, (%r9));	\
SUFFIX_LABEL (ICMPXCHGQ_EQ):	\
  PCMPXCHG (q, %rbx, (%r9));	\
SUFFIX_LABEL (ICMPXCHGQ_NE):	\
				\
  movq	$0, %rax;		\
SUFFIX_LABEL (IMCMPQ1):		\
  movq	$1, %rbx;		\
SUFFIX_LABEL (IMCMPQ2):		\
  PCMP (q, %rax, (%r10));	\
SUFFIX_LABEL (ICMPQ_EQ):	\
  PCMP (q, %rbx, (%r10));	\
SUFFIX_LABEL (ICMPQ_NE):	\
				\
  movl	$__NR_getpid, %eax;	\
SUFFIX_LABEL (ISNR):		\
  PSYSCALL;			\
SUFFIX_LABEL (ISYS):		\
				\
  movq	jmp_mem, %rcx;		\
SUFFIX_LABEL (IMJMP):		\
  PSYNC (jmp	*%rcx;)		\
  nop;				\
SUFFIX_LABEL (IJMP):		\
				\
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
#define RAW_STOR(sz, imm_or_reg, mem) \
  _ERS_PASTE (mov, sz)	imm_or_reg, mem
#define RAW_LOAD(sz, mem, reg)	_ERS_PASTE (mov, sz)	mem, reg
#define RAW_CMPXCHG(sz, reg, mem) \
  _ERS_PASTE (cmpxchg, sz)	reg, mem
#define RAW_CMP(sz, reg, mem)	_ERS_PASTE (cmp, sz)	reg, mem
#define RAW_SYSCALL		syscall
#define RAW_SYNC(inst)		inst

#define PXCHG			RAW_XCHG
#define PINC			RAW_INC
#define PSTOR			RAW_STOR
#define PLOAD			RAW_LOAD
#define PCMPXCHG		RAW_CMPXCHG
#define PCMP			RAW_CMP
#define PSYSCALL		RAW_SYSCALL
#define PSYNC			RAW_SYNC

#define SUF			_raw

  PROCESS
  call	process
1:

#undef PXCHG
#undef PINC
#undef PSTOR
#undef PLOAD
#undef PCMPXCHG
#undef PCMP
#undef PSYSCALL
#undef PSYNC
#undef SUF

#ifdef TST_XCHG
# define PXCHG(sz, reg, mem)	_ERS_ATOMIC_XCHG (sz, reg, mem)
#else
# define PXCHG			RAW_XCHG
#endif

#ifdef TST_INC
# define PINC(sz, mem)		_ERS_ATOMIC_INC (sz, mem)
#else
# define PINC			RAW_INC
#endif

#ifdef TST_STOR
# define PSTOR(sz, imm_or_reg, mem) \
  _ERS_ATOMIC_STOR (sz, imm_or_reg, mem)
#else
# define PSTOR			RAW_STOR
#endif

#ifdef TST_LOAD
# define PLOAD(sz, mem, reg) \
  _ERS_ATOMIC_LOAD (sz, mem, reg)
#else
# define PLOAD			RAW_LOAD
#endif

#ifdef TST_CMPXCHG
# define PCMPXCHG(sz, reg, mem)	_ERS_ATOMIC_CMPXCHG (sz, reg, mem)
#else
# define PCMPXCHG		RAW_CMPXCHG
#endif

#ifdef TST_CMP
# define PCMP(sz, reg, mem) 	PERS_ATOMIC_CMP (sz, reg, mem)
#else
# define PCMP			RAW_CMP
#endif

#ifdef TST_SYSCALL
# define PSYSCALL		_ERS_SYSCALL
#else
# define PSYSCALL		RAW_SYSCALL
#endif

#ifdef TST_SYNC
# define PSYNC			_ERS_SYNC_ASYNC
#else
# define PSYNC			RAW_SYNC
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
