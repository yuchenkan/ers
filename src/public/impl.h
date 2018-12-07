#ifndef _ERS_PUBLIC_IMPL_H
#define _ERS_PUBLIC_IMPL_H

#include "public/comm.h"
#include "public/recorder-offsets.h"

#define _ERS_ATOMIC_OP(op, sz) \
  _ERS_OP (_ERS_PASTE (_ERS_OP_ATOMIC_, op), _ERS_ATOMIC_SIZE (sz))

#define _ERS_ENTER(mark, op) \
  movq	$_ERS_PASTE (_ERS_MARK_, mark), %gs:_ERS_COMMON_THREAD_MARK;	\
  movq	$op, %gs:_ERS_COMMON_THREAD_OP;					\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_RBX

#define _ERS_SAVE_LABEL(label, off) \
  leaq	label(%rip), %rbx;						\
  movq	%rbx, %gs:_ERS_PASTE (_ERS_COMMON_THREAD_, off)

#define _ERS_SAVE_START(label)	_ERS_SAVE_LABEL (label, START)
#define _ERS_SAVE_RET(label)	_ERS_SAVE_LABEL (label, RET)
#define _ERS_SAVE_CONT(label)	_ERS_SAVE_LABEL (label, CONT)

#define _ERS_DIR \
  /* This has to be before jumping to dir, so that if mark is 1,  */	\
  /* we have chance to run and return to sigaction. After this, */	\
  /* if we get sginal we have to manually fix the context.  */		\
  movq	$0, %gs:_ERS_COMMON_THREAD_MARK;				\
  jmp	*%gs:_ERS_COMMON_THREAD_DIR

#define _ERS_SYSCALL \
30:									\
  _ERS_ENTER (INTERNAL_RET, _ERS_OP (_ERS_OP_SYSCALL, 0));		\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_CONT (20f);							\
  jmp	*%gs:_ERS_COMMON_THREAD_THREAD_ENTRY;				\
20:

#define _ERS_SYNC_ASYNC(inst) \
30:									\
  _ERS_ENTER (EXTERNAL_RET, _ERS_OP (_ERS_OP_SYNC_ASYNC, 0));		\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_RET (20f);							\
  jmp	*%gs:_ERS_COMMON_THREAD_THREAD_ENTRY;				\
20:									\
  inst

#define _ERS_ATOMIC_SAVE_MEM(mem) \
  leaq	mem, %rbx;							\
  movq	%rbx, %gs:_ERS_COMMON_THREAD_VAR1

#define _ERS_ATOMIC_XCHG(sz, reg, mem) \
30:									\
  _ERS_ENTER (EXTERNAL_RET, _ERS_ATOMIC_OP (XCHG, sz));			\
									\
  movq	$0, %gs:_ERS_COMMON_THREAD_VAR0;				\
  _ERS_PASTE (mov, sz)	reg, %gs:_ERS_COMMON_THREAD_VAR0;		\
  _ERS_ATOMIC_SAVE_MEM (mem);						\
									\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_RET (10f);							\
  _ERS_SAVE_CONT (20f);							\
  jmp	*%gs:_ERS_COMMON_THREAD_THREAD_ENTRY;				\
10:									\
  _ERS_PASTE (mov, sz)	%gs:_ERS_COMMON_THREAD_VAR0, reg;		\
  _ERS_DIR;								\
20:

#define _ERS_ATOMIC_INC(sz, mem) \
30:									\
  _ERS_ENTER (INTERNAL_RET, _ERS_ATOMIC_OP (INC, sz));			\
  _ERS_ATOMIC_SAVE_MEM (mem);						\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_CONT (20f);							\
  jmp	*%gs:_ERS_COMMON_THREAD_THREAD_ENTRY;				\
20:

#endif
