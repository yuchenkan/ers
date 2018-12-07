#ifndef ERI_TST_TST_LIVE_ENTRY_H
#define ERI_TST_TST_LIVE_ENTRY_H

#include "public/comm.h"

#define INOP	0

#define IXCHGB	1
#define IXCHGW	2
#define IXCHGL	3
#define IXCHGQ	4

#define IINCB	5
#define IINCW	6
#define IINCL	7
#define IINCQ	8

#define IMSTORQ	9
#define ISTORQ	10
#define ILSTORQ	11

#define IMSTORL	12
#define ISTORL	13
#define ILSTORL	14

#define IMSTORW	15
#define ISTORW	16
#define ILSTORW	17

#define IMSTORB	18
#define ISTORB	19
#define ILSTORB	20

#define ISNR	21
#define ISYS	22

#define IMJMP	23
#define IJMP	24

#define IPUFQ	25
#define ISTF	26
#define IPOFQ	27

#define LABEL(i)			_ERS_PASTE (label, i)

#define ATOMIC_COMM_OP(at_op, at, a, b, c, d, ...) \
  at_op (_ERS_PASTE (at, a), ##__VA_ARGS__)				\
  at_op (_ERS_PASTE (at, b), ##__VA_ARGS__)				\
  at_op (_ERS_PASTE (at, c), ##__VA_ARGS__)				\
  at_op (_ERS_PASTE (at, d), ##__VA_ARGS__)

#define ATOMIC_OP(at_op, at, ...) \
  ATOMIC_COMM_OP (at_op, at, B, W, L, Q, ##__VA_ARGS__)

#define ATOMIC_REV_OP(at_op, at, ...) \
  ATOMIC_COMM_OP (at_op, at, Q, L, W, B, ##__VA_ARGS__)

#define LABEL_OP(name, l_op)		l_op (LABEL (_ERS_PASTE (I, name)))

#define ATOMIC_LABELS(l_op, at)		ATOMIC_OP (LABEL_OP, at, l_op)
#define ATOMIC_REV_LABELS(l_op, at)	ATOMIC_REV_OP (LABEL_OP, at, l_op)

#define ATOMIC_STOR_SIZE_LABELS(at, l_op) \
  LABEL_OP (_ERS_PASTE (M, at), l_op) LABEL_OP (at, l_op)		\
  LABEL_OP (_ERS_PASTE (L, at), l_op)

#define ATOMIC_STOR_LABELS(l_op) \
  ATOMIC_REV_OP (ATOMIC_STOR_SIZE_LABELS, STOR, l_op)

#define LABELS(l_op) \
  LABEL_OP (NOP, l_op)							\
  ATOMIC_LABELS (l_op, XCHG) ATOMIC_LABELS (l_op, INC)			\
  ATOMIC_STOR_LABELS (l_op)						\
  LABEL_OP (SNR, l_op) LABEL_OP (SYS, l_op) LABEL_OP (MJMP, l_op)	\
  LABEL_OP (JMP, l_op) LABEL_OP (PUFQ, l_op) LABEL_OP (STF, l_op)	\
  LABEL_OP (POFQ, l_op)

#define SUFFIX(name)		_ERS_PASTE (name, SUF)

#define TST_XCHG
#define TST_INC
#define TST_STOR
#define TST_SYSCALL
#define TST_SYNC

#endif
