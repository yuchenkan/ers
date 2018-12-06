#include "public/comm.h"

#define INOP	0
#define IXCHG	1
#define ISNR	2
#define ISYS	3
#define IMJMP	4
#define IJMP	5
#define IPUFQ	6
#define ISTF	7
#define IPOFQ	8

#define L(i)	_ERS_PASTE (l, i)
#define LS(op) \
  op (L (INOP)) op (L (IXCHG)) op (L (ISNR)) op (L (ISYS))	\
  op (L (IMJMP)) op (L (IJMP)) op (L (IPUFQ)) op (L (ISTF)) op (L (IPOFQ))

#define TT_XCHG
#define TT_SYSCALL
#define TT_SYNC
