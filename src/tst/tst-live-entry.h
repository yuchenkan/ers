#ifndef ERI_TST_TST_LIVE_ENTRY_H
#define ERI_TST_TST_LIVE_ENTRY_H

#include "public/comm.h"

#define INOP	0
#define IXCHGB	1
#define IXCHGW	2
#define IXCHGL	3
#define IXCHGQ	4
#define ISNR	5
#define ISYS	6
#define IMJMP	7
#define IJMP	8
#define IPUFQ	9
#define ISTF	10
#define IPOFQ	11

#define LABEL(i)		_ERS_PASTE (label, i)
#define LABELS(op) \
  op (LABEL (INOP)) op (LABEL (IXCHGB)) op (LABEL (IXCHGW))		\
  op (LABEL (IXCHGL)) op (LABEL (IXCHGQ)) op (LABEL (ISNR))		\
  op (LABEL (ISYS)) op (LABEL (IMJMP)) op (LABEL (IJMP))		\
  op (LABEL (IPUFQ)) op (LABEL (ISTF)) op (LABEL (IPOFQ))

#define SUFFIX(label)		_ERS_PASTE (label, SUF)

#define TST_XCHG
#define TST_SYSCALL
#define TST_SYNC

#endif
