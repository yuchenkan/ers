#ifndef _ERS_PUBLIC_COMMON_H
#define _ERS_PUBLIC_COMMON_H

#define __ERS_STR(x)		#x
#define _ERS_STR(x)		__ERS_STR (x)

#define __ERS_PASTE(x, y)	x##y
#define _ERS_PASTE(x, y)	__ERS_PASTE (x, y)

#define _ERS_PASTE2(x, y,z)	_ERS_PASTE (_ERS_PASTE (x, y), z)

#define _ERS_EVAL(...) __VA_ARGS__

#define _ERS_MARK_EXTERNAL_RET	1
#define _ERS_MARK_INTERNAL_RET	2

#define _ERS_OP_SYSCALL		1
#define _ERS_OP_SYNC_ASYNC	2

#define _ERS_OP_ATOMIC_LOAD	3
#define _ERS_OP_ATOMIC_STOR	4
#define _ERS_OP_ATOMIC_INC	5
#define _ERS_OP_ATOMIC_DEC	6
#define _ERS_OP_ATOMIC_XCHG	7
#define _ERS_OP_ATOMIC_CMPXCHG	8

#define _ERS_OP_FLAGS_BITS	4
#define _ERS_OP_FLAGS_MASK	((1 << _ERS_OP_FLAGS_BITS) - 1)

#define _ERS_OP(op, flags)	(((op) << _ERS_OP_FLAGS_BITS) | (flags))
#define _ERS_OP_OP(op)		((op) >> _ERS_OP_FLAGS_BITS)
#define _ERS_OP_FLAGS(op)	(op & _ERS_OP_FLAGS_MASK)

#define _ERS_ATOMIC_SIZE_b	0
#define _ERS_ATOMIC_SIZE_w	1
#define _ERS_ATOMIC_SIZE_l	2
#define _ERS_ATOMIC_SIZE_q	3
#define _ERS_ATOMIC_SIZE(sz)	_ERS_PASTE (_ERS_ATOMIC_SIZE_, sz)

#if 0

#define _ERS_ATOMIC_LOAD	0x1000
#define _ERS_ATOMIC_STOR	0x1001

#define _ERS_ATOMIC_INC		0x1002
#define _ERS_ATOMIC_DEC		0x1003
#define _ERS_ATOMIC_ADD		0x1004
#define _ERS_ATOMIC_SUB		0x1005
#define _ERS_ATOMIC_ADC		0x1006
#define _ERS_ATOMIC_SBB		0x1007
#define _ERS_ATOMIC_NEG		0x1008
#define _ERS_ATOMIC_AND		0x1009
#define _ERS_ATOMIC_OR		0x100a
#define _ERS_ATOMIC_XOR		0x100b
#define _ERS_ATOMIC_NOT		0x100c
#define _ERS_ATOMIC_BTC		0x100d
#define _ERS_ATOMIC_BTR		0x100e
#define _ERS_ATOMIC_BTS		0x100f
#define _ERS_ATOMIC_XCHG	0x1010
#define _ERS_ATOMIC_XADD	0x1011
#define _ERS_ATOMIC_CMPXCHG	0x1012
#define _ERS_ATOMIC_XCHG8B	0x1013
#define _ERS_ATOMIC_XCHG16B	0x1014

#endif

#endif
