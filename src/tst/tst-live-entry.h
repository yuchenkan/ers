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
#define ISNR	9
#define ISYS	10
#define IMJMP	11
#define IJMP	12
#define IPUFQ	13
#define ISTF	14
#define IPOFQ	15

#define LABEL(i)		_ERS_PASTE (label, i)

#define ATOMIC_LABELS(op, at) \
  op (LABEL (_ERS_PASTE (at, B))) op (LABEL (_ERS_PASTE (at, W)))	\
  op (LABEL (_ERS_PASTE (at, L))) op (LABEL (_ERS_PASTE (at, Q)))

#define LABELS(op) \
  op (LABEL (INOP))							\
  ATOMIC_LABELS (op, IXCHG) ATOMIC_LABELS (op, IINC)			\
  op (LABEL (ISNR)) op (LABEL (ISYS)) op (LABEL (IMJMP))		\
  op (LABEL (IJMP)) op (LABEL (IPUFQ)) op (LABEL (ISTF))		\
  op (LABEL (IPOFQ))

#define SUFFIX(label)		_ERS_PASTE (label, SUF)

#define TST_XCHG
#define TST_INC
#define TST_SYSCALL
#define TST_SYNC

#endif
