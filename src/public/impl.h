#ifndef _ERS_PUBLIC_IMPL_IMPL_H
#define _ERS_PUBLIC_IMPL_IMPL_H

#include <public/util.h>
#include <public/entry-offsets.h>

#include <live/live.h>

#define _ERS_ATOMIC_SIZE_b	0
#define _ERS_ATOMIC_SIZE_w	1
#define _ERS_ATOMIC_SIZE_l	2
#define _ERS_ATOMIC_SIZE_q	3
#define _ERS_ATOMIC_SIZE(sz)	_ERS_PASTE (_ERS_ATOMIC_SIZE_, sz)

#ifndef _ERS_EXPORT
# define _ERS_EXP_CONST(x)		(x)
# define _ERS_EXP_PASTE(x, y)		_ERS_PASTE (x, y)
# define _ERS_EXP_REG(e, reg)		_ERS_PP_IF (e, %)%reg
# define _ERS_EXP_ATOMIC_SIZE(sz)	_ERS_ATOMIC_SIZE (sz)
#endif

#define _ERS_INIT \
  .align 16, 0x90;							\
  _ERS_LIVE_RTLD

#define _ERS_REG(e, reg)	_ERS_EXP_REG (e, reg)
#define _ERS_RBX(e)		_ERS_REG (e, rbx)
#define _ERS_RIP(e)		_ERS_REG (e, rip)

#define _ERS_ENTRY(e, field) \
  _ERS_REG (e, gs):_ERS_PASTE (_ERS_ENTRY_, field)

#define _ERS_ENTER(e, op) \
  movq	$(op), _ERS_ENTRY (e, OP);					\
  movq	_ERS_RBX (e), _ERS_ENTRY (e, RBX)

#define _ERS_SAVE_LABEL(e, label, field) \
  leaq	label(_ERS_RIP (e)), _ERS_RBX (e);				\
  movq	_ERS_RBX (e), _ERS_ENTRY (e, field)

#define _ERS_SAVE_START(e, label)	_ERS_SAVE_LABEL (e, label, START)
#define _ERS_SAVE_LEAVE(e, label)	_ERS_SAVE_LABEL (e, label, LEAVE)

#define _ERS_OP(code, args) \
  (_ERS_EXP_CONST (_ERS_PASTE (_ERS_OP_, code) << 16) | ((args) << 8))

#define _ERS_SYSCALL(e) \
30:									\
  _ERS_ENTER (e, _ERS_EXP_CONST (_ERS_OP (SYSCALL, 0)));		\
  _ERS_SAVE_START (e, 30b);						\
  _ERS_SAVE_LEAVE (e, 20f);						\
  jmp	*_ERS_ENTRY (e, ENTER);						\
20:

#define _ERS_SYNC_ASYNC(e, inst) \
30:									\
  _ERS_ENTER (e, _ERS_EXP_CONST (_ERS_OP (SYNC_ASYNC, 0)));		\
  _ERS_SAVE_START (e, 30b);						\
  _ERS_SAVE_LEAVE (e, 20f);						\
  jmp	*_ERS_ENTRY (e, ENTER);						\
20:									\
  inst

#define _ERS_ATOMIC_OP(op, sz) \
  _ERS_OP (_ERS_PASTE (ATOMIC_, op), _ERS_EXP_ATOMIC_SIZE (sz))

#define _ERS_ATOMIC_SAVE_VAL(e, sz, val) \
  _ERS_EXP_PASTE (mov, sz)	val, _ERS_ENTRY (e, ATOMIC_VAL)

#define _ERS_ATOMIC_SAVE_MEM(e, mem) \
  leaq	mem, _ERS_RBX (e);						\
  movq	_ERS_RBX (e), _ERS_ENTRY (e, ATOMIC_MEM)

#define _ERS_ATOMIC_SAVE_LEAVE(e, label) \
  _ERS_SAVE_LABEL (e, label, ATOMIC_LEAVE)

#define _ERS_ATOMIC_COMMON_LOAD(e, sz, mem, op, ...) \
30:									\
  _ERS_ENTER (e, _ERS_ATOMIC_OP (LOAD, sz));				\
  _ERS_ATOMIC_SAVE_MEM (e, mem);					\
  _ERS_SAVE_START (e, 30b);						\
  _ERS_SAVE_LEAVE (e, 10f);						\
  _ERS_ATOMIC_SAVE_LEAVE (e, 20f);					\
  jmp	*_ERS_ENTRY (e, ENTER);						\
10:									\
  op (sz, _ERS_ENTRY (e, ATOMIC_VAL), ##__VA_ARGS__);			\
  movq	_ERS_RBX (e), _ERS_ENTRY (e, RBX);				\
  jmp	*_ERS_ENTRY (e, ENTER);						\
20:

#define _ERS_LOAD_LOAD(sz, res, reg) \
  _ERS_EXP_PASTE (mov, sz)	res, reg

#define _ERS_ATOMIC_LOAD(e, sz, mem, reg) \
  _ERS_ATOMIC_COMMON_LOAD (e, sz, mem, _ERS_LOAD_LOAD, reg)

#define _ERS_ATOMIC_COMMON2(op, e, sz, reg, mem) \
30:									\
  _ERS_ENTER (e, _ERS_ATOMIC_OP (op, sz));				\
  _ERS_ATOMIC_SAVE_VAL (e, sz, reg);					\
  _ERS_ATOMIC_SAVE_MEM (e, mem);					\
  _ERS_SAVE_START (e, 30b);						\
  _ERS_SAVE_LEAVE (e, 20f);						\
  jmp	*_ERS_ENTRY (e, ENTER);						\
20:

#define _ERS_ATOMIC_XCOMMON2(op, e, sz, reg, mem) \
30:									\
  _ERS_ENTER (e, _ERS_ATOMIC_OP (op, sz));				\
  _ERS_ATOMIC_SAVE_VAL (e, sz, reg);					\
  _ERS_ATOMIC_SAVE_MEM (e, mem);					\
  _ERS_SAVE_START (e, 30b);						\
  _ERS_SAVE_LEAVE (e, 10f);						\
  _ERS_ATOMIC_SAVE_LEAVE (e, 20f);					\
  jmp	*_ERS_ENTRY (e, ENTER);						\
10:									\
  _ERS_EXP_PASTE (mov, sz)	_ERS_ENTRY (e, ATOMIC_VAL), reg;	\
  movq	_ERS_RBX (e), _ERS_ENTRY (e, RBX);				\
  jmp	*_ERS_ENTRY (e, ENTER);						\
20:

/* mov	imm8/16/32/r8/16/32/64, m8/16/32/64  */
#define _ERS_ATOMIC_STORE(e, sz, imm_or_reg, mem) \
  _ERS_ATOMIC_COMMON2 (STORE, e, sz, imm_or_reg, mem)

#define _ERS_ATOMIC_INC_DEC(e, sz, mem, op) \
30:									\
  _ERS_ENTER (e, _ERS_ATOMIC_OP (op, sz));				\
  _ERS_ATOMIC_SAVE_MEM (e, mem);					\
  _ERS_SAVE_START (e, 30b);						\
  _ERS_SAVE_LEAVE (e, 20f);						\
  jmp	*_ERS_ENTRY (e, ENTER);						\
20:

#define _ERS_ATOMIC_INC(e, sz, mem)	_ERS_ATOMIC_INC_DEC (e, sz, mem, INC)
#define _ERS_ATOMIC_DEC(e, sz, mem)	_ERS_ATOMIC_INC_DEC (e, sz, mem, DEC)

#define _ERS_ATOMIC_XCHG(e, sz, reg, mem) \
  _ERS_ATOMIC_XCOMMON2 (XCHG, e, sz, reg, mem)

#define _ERS_ATOMIC_CMPXCHG(e, sz, reg, mem) \
  _ERS_ATOMIC_COMMON2 (CMPXCHG, e, sz, reg, mem)

#define _ERS_ATOMIC_ADD(e, sz, reg, mem) \
  _ERS_ATOMIC_COMMON2 (ADD, e, sz, reg, mem)

#define _ERS_ATOMIC_AND(e, sz, reg, mem) \
  _ERS_ATOMIC_COMMON2 (AND, e, sz, reg, mem)

#define _ERS_ATOMIC_OR(e, sz, reg, mem) \
  _ERS_ATOMIC_COMMON2 (OR, e, sz, reg, mem)

#define _ERS_ATOMIC_XOR(e, sz, reg, mem) \
  _ERS_ATOMIC_COMMON2 (XOR, e, sz, reg, mem)

#define _ERS_ATOMIC_XADD(e, sz, reg, mem) \
  _ERS_ATOMIC_XCOMMON2 (XADD, e, sz, reg, mem)

#endif
