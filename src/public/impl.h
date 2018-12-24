#ifndef _ERS_PUBLIC_IMPL_H
#define _ERS_PUBLIC_IMPL_H

#include "public/common.h"
#ifndef ERI_TST_RTLD
/* # include "public/rtld.h" */
#else
# include "public/tst-rtld.h"
#endif
#include "public/entry-offsets.h"

#define _ERS_INIT \
  .align 16, 0x90;							\
  _ERS_RTLD

#define _ERS_ENTRY(field)	%gs:_ERS_PASTE (_ERS_THREAD_ENTRY_, field)

#define _ERS_ENTER(mark, op) \
  movq	$_ERS_PASTE (_ERS_MARK_, mark), _ERS_ENTRY (MARK);		\
  movq	$op, _ERS_ENTRY (OP);						\
  movq	%rbx, _ERS_ENTRY (RBX)

#define _ERS_SAVE_LABEL(label, field) \
  leaq	label(%rip), %rbx;						\
  movq	%rbx, _ERS_ENTRY (field)

#define _ERS_SAVE_START(label)	_ERS_SAVE_LABEL (label, START)
#define _ERS_SAVE_RET(label)	_ERS_SAVE_LABEL (label, RET)
#define _ERS_SAVE_CONT(label)	_ERS_SAVE_LABEL (label, CONT)

#define _ERS_DIR \
  /* This has to be before jumping to dir, so that if mark is 1,  */	\
  /* we have chance to run and return to sigaction. After this, */	\
  /* if we get sginal we have to manually fix the context.  */		\
  movq	$0, _ERS_ENTRY (MARK);						\
  jmp	*_ERS_ENTRY (DIR)

#define _ERS_SYSCALL \
30:									\
  _ERS_ENTER (INTERNAL_RET, _ERS_OP (_ERS_OP_SYSCALL, 0));		\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_CONT (20f);							\
  jmp	*_ERS_ENTRY (THREAD_ENTRY);					\
20:

#define _ERS_SYNC_ASYNC(inst) \
30:									\
  _ERS_ENTER (EXTERNAL_RET, _ERS_OP (_ERS_OP_SYNC_ASYNC, 0));		\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_RET (20f);							\
  jmp	*_ERS_ENTRY (THREAD_ENTRY);					\
20:									\
  inst

#define _ERS_ATOMIC_OP(op, sz) \
  _ERS_OP (_ERS_PASTE (_ERS_OP_ATOMIC_, op), _ERS_ATOMIC_SIZE (sz))

#define _ERS_ATOMIC_SAVE_VAL(sz, val) \
  movq	$0, _ERS_ENTRY (VAR0);						\
  _ERS_PASTE (mov, sz)	val, _ERS_ENTRY (VAR0)

#define _ERS_ATOMIC_SAVE_MEM(mem) \
  leaq	mem, %rbx;							\
  movq	%rbx, _ERS_ENTRY (VAR1)

#define _ERS_ATOMIC_COMMON_LOAD(sz, mem, op, ...) \
30:									\
  _ERS_ENTER (EXTERNAL_RET, _ERS_ATOMIC_OP (LOAD, sz));			\
  _ERS_ATOMIC_SAVE_MEM (mem);						\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_RET (10f);							\
  _ERS_SAVE_CONT (20f);							\
  jmp	*_ERS_ENTRY (THREAD_ENTRY);					\
10:									\
  op (sz, _ERS_ENTRY (VAR0), ##__VA_ARGS__);				\
  _ERS_DIR;								\
20:

#define _ERS_LOAD_LOAD(sz, res, reg) \
  _ERS_PASTE (mov, sz)	res, reg

#define _ERS_ATOMIC_LOAD(sz, mem, reg) \
  _ERS_ATOMIC_COMMON_LOAD (sz, mem, _ERS_LOAD_LOAD, reg)

/* mov	imm8/16/32/r8/16/32/64, m8/16/32/64  */
#define _ERS_ATOMIC_STORE(sz, imm_or_reg, mem) \
30:									\
  _ERS_ENTER (INTERNAL_RET, _ERS_ATOMIC_OP (STORE, sz));		\
  _ERS_ATOMIC_SAVE_VAL (sz, imm_or_reg);				\
  _ERS_ATOMIC_SAVE_MEM (mem);						\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_CONT (20f);							\
  jmp	*_ERS_ENTRY (THREAD_ENTRY);					\
20:

#define _ERS_ATOMIC_INC_DEC(sz, mem, op) \
30:									\
  _ERS_ENTER (INTERNAL_RET, _ERS_ATOMIC_OP (op, sz));			\
  _ERS_ATOMIC_SAVE_MEM (mem);						\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_CONT (20f);							\
  jmp	*_ERS_ENTRY (THREAD_ENTRY);					\
20:

#define _ERS_ATOMIC_INC(sz, mem)	_ERS_ATOMIC_INC_DEC (sz, mem, INC)
#define _ERS_ATOMIC_DEC(sz, mem)	_ERS_ATOMIC_INC_DEC (sz, mem, DEC)

#define _ERS_ATOMIC_XCHG(sz, reg, mem) \
30:									\
  _ERS_ENTER (EXTERNAL_RET, _ERS_ATOMIC_OP (XCHG, sz));			\
  _ERS_ATOMIC_SAVE_VAL (sz, reg);					\
  _ERS_ATOMIC_SAVE_MEM (mem);						\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_RET (10f);							\
  _ERS_SAVE_CONT (20f);							\
  jmp	*_ERS_ENTRY (THREAD_ENTRY);					\
10:									\
  _ERS_PASTE (mov, sz)	_ERS_ENTRY (VAR0), reg;				\
  _ERS_DIR;								\
20:

#define _ERS_ATOMIC_CMPXCHG(sz, reg, mem) \
30:									\
  _ERS_ENTER (INTERNAL_RET, _ERS_ATOMIC_OP (CMPXCHG, sz));		\
  _ERS_ATOMIC_SAVE_VAL (sz, reg);					\
  _ERS_ATOMIC_SAVE_MEM (mem);						\
  _ERS_SAVE_START (30b);						\
  _ERS_SAVE_CONT (20f);							\
  jmp	*_ERS_ENTRY (THREAD_ENTRY);					\
20:

#endif
