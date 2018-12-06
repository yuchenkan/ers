#ifndef _ERS_PUBLIC_IMPL_H
#define _ERS_PUBLIC_IMPL_H

#include "public/comm.h"
#include "public/recorder-offsets.h"

#define _ERS_XCHG(a, b) \
30:					\
  movq	$_ERS_MARK_EXTERNAL_RET, %gs:_ERS_COMMON_THREAD_MARK;	/* 1 */	\
  movq	$_ERS_OP_XCHG, %gs:_ERS_COMMON_THREAD_OP;	\
  movq	a, %gs:_ERS_COMMON_THREAD_VAR0;		\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_RBX;		\
  leaq	b, %rbx;			\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_VAR1;		\
					\
  leaq	30b(%rip), %rbx;		\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_START;		\
					\
  leaq	10f(%rip), %rbx;		\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_RET;		\
					\
  leaq	20f(%rip), %rbx;		\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_CONT;		\
  jmp	*%gs:_ERS_COMMON_THREAD_THREAD_ENTRY;		/* 13 */	\
10:					\
  movq	%gs:_ERS_COMMON_THREAD_VAR0, a;		\
  /* This has to be before jumping to dir, so that if mark is 1,  */	\
  /* we have chance to run and return to dir. After this, if we get */	\
  /* sginal we have to manually fix the context, which are rip and */	\
  /* dir (see .lxchg_complete_start).  */		\
  movq	$0, %gs:_ERS_COMMON_THREAD_MARK;		\
  jmp	*%gs:_ERS_COMMON_THREAD_DIR;		\
20:					\

#define _ERS_SYSCALL \
30:					\
  movq	$_ERS_MARK_INTERNAL_RET, %gs:_ERS_COMMON_THREAD_MARK;		\
  movq	$_ERS_OP_SYSCALL, %gs:_ERS_COMMON_THREAD_OP;	\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_RBX;		\
					\
  leaq	30b(%rip), %rbx;		\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_START;		\
					\
  leaq	20f(%rip), %rbx;		\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_CONT;		\
  jmp	*%gs:_ERS_COMMON_THREAD_THREAD_ENTRY;			\
20:

#define _ERS_SYNC(i) \
30:					\
  movq	$_ERS_MARK_EXTERNAL_RET, %gs:_ERS_COMMON_THREAD_MARK;		\
  movq	$_ERS_OP_SYNC, %gs:_ERS_COMMON_THREAD_OP;	\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_RBX;		\
					\
  leaq	30b(%rip), %rbx;		\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_START;		\
					\
  leaq	20f(%rip), %rbx;		\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_RET;		\
  jmp	*%gs:_ERS_COMMON_THREAD_THREAD_ENTRY;		/* 8 */	\
20:					\
  i

#endif
