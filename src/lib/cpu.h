#ifndef ERI_LIB_CPU_H
#define ERI_LIB_CPU_H

#include <lib/util.h>

#define _ERI_R0_b(i)		ERI_PASTE (i, l)
#define _ERI_R0_w(i)		ERI_PASTE (i, x)
#define _ERI_R0_l(i)		ERI_PASTE2 (e, i, x)
#define _ERI_R0_q(i)		ERI_PASTE2 (r, i, x)

#define ERI_RAX(sz)		ERI_PASTE (_ERI_R0_, sz) (a)
#define ERI_RBX(sz)		ERI_PASTE (_ERI_R0_, sz) (b)
#define ERI_RDX(sz)		ERI_PASTE (_ERI_R0_, sz) (d)
#define ERI_RCX(sz)		ERI_PASTE (_ERI_R0_, sz) (c)

#define _ERI_R1_b(i)		ERI_PASTE (i, l)
#define _ERI_R1_w(i)		i
#define _ERI_R1_l(i)		ERI_PASTE (e, i)
#define _ERI_R1_q(i)		ERI_PASTE (r, i)

#define ERI_RDI(sz)		ERI_PASTE (_ERI_R1_, sz) (di)
#define ERI_RSI(sz)		ERI_PASTE (_ERI_R1_, sz) (si)
#define ERI_RSP(sz)		ERI_PASTE (_ERI_R1_, sz) (sp)
#define ERI_RBP(sz)		ERI_PASTE (_ERI_R1_, sz) (bp)

#define _ERI_R2_b(i)		ERI_PASTE (i, b)
#define _ERI_R2_w(i)		ERI_PASTE (i, w)
#define _ERI_R2_l(i)		ERI_PASTE (i, d)
#define _ERI_R2_q(i)		i

#define ERI_R8(sz)		ERI_PASTE (_ERI_R2_, sz) (r8)
#define ERI_R9(sz)		ERI_PASTE (_ERI_R2_, sz) (r9)
#define ERI_R10(sz)		ERI_PASTE (_ERI_R2_, sz) (r10)
#define ERI_R11(sz)		ERI_PASTE (_ERI_R2_, sz) (r11)
#define ERI_R12(sz)		ERI_PASTE (_ERI_R2_, sz) (r12)
#define ERI_R13(sz)		ERI_PASTE (_ERI_R2_, sz) (r13)
#define ERI_R14(sz)		ERI_PASTE (_ERI_R2_, sz) (r14)
#define ERI_R15(sz)		ERI_PASTE (_ERI_R2_, sz) (r15)

#define _ERI_CR0_b(i)		ERI_PASTE (i, L)
#define _ERI_CR0_w(i)		ERI_PASTE (i, X)
#define _ERI_CR0_l(i)		ERI_PASTE2 (E, i, X)
#define _ERI_CR0_q(i)		ERI_PASTE2 (R, i, X)

#define ERI_CRAX(sz)		ERI_PASTE (_ERI_CR0_, sz) (A)
#define ERI_CRBX(sz)		ERI_PASTE (_ERI_CR0_, sz) (B)
#define ERI_CRDX(sz)		ERI_PASTE (_ERI_CR0_, sz) (D)
#define ERI_CRCX(sz)		ERI_PASTE (_ERI_CR0_, sz) (C)

#define _ERI_CR1_b(i)		ERI_PASTE (i, L)
#define _ERI_CR1_w(i)		i
#define _ERI_CR1_l(i)		ERI_PASTE (E, i)
#define _ERI_CR1_q(i)		ERI_PASTE (R, i)

#define ERI_CRDI(sz)		ERI_PASTE (_ERI_CR1_, sz) (DI)
#define ERI_CRSI(sz)		ERI_PASTE (_ERI_CR1_, sz) (SI)
#define ERI_CRSP(sz)		ERI_PASTE (_ERI_CR1_, sz) (SP)
#define ERI_CRBP(sz)		ERI_PASTE (_ERI_CR1_, sz) (BP)

#define _ERI_CR2_b(i)		ERI_PASTE (i, B)
#define _ERI_CR2_w(i)		ERI_PASTE (i, W)
#define _ERI_CR2_l(i)		ERI_PASTE (i, D)
#define _ERI_CR2_q(i)		i

#define ERI_CR8(sz)		ERI_PASTE (_ERI_CR2_, sz) (R8)
#define ERI_CR9(sz)		ERI_PASTE (_ERI_CR2_, sz) (R9)
#define ERI_CR10(sz)		ERI_PASTE (_ERI_CR2_, sz) (R10)
#define ERI_CR11(sz)		ERI_PASTE (_ERI_CR2_, sz) (R11)
#define ERI_CR12(sz)		ERI_PASTE (_ERI_CR2_, sz) (R12)
#define ERI_CR13(sz)		ERI_PASTE (_ERI_CR2_, sz) (R13)
#define ERI_CR14(sz)		ERI_PASTE (_ERI_CR2_, sz) (R14)
#define ERI_CR15(sz)		ERI_PASTE (_ERI_CR2_, sz) (R15)

#define ERI_FOREACH_REG_SIZE3(p, ...) \
  p (b, ##__VA_ARGS__)							\
  p (w, ##__VA_ARGS__)							\
  p (l, ##__VA_ARGS__)

#define ERI_FOREACH_REG_SIZE(p, ...) \
  ERI_FOREACH_REG_SIZE3 (p, ##__VA_ARGS__)				\
  p (q, ##__VA_ARGS__)

#define ERI_RFLAGS_ZF		(1 << 6)
#define ERI_RFLAGS_TF		(1 << 8)
#define ERI_RFLAGS_DF		(1 << 10)
#define ERI_RFLAGS_RF		(1 << 16)

/* XXX: check other flags */
#define ERI_RFLAGS_STATUS_MASK	0xd5

#define ERI_FOREACH_GPREG_NO_RBX_RSP(p, ...) \
  p (RAX, rax, ##__VA_ARGS__)						\
  p (RCX, rcx, ##__VA_ARGS__)						\
  p (RDX, rdx, ##__VA_ARGS__)						\
  p (RSI, rsi, ##__VA_ARGS__)						\
  p (RDI, rdi, ##__VA_ARGS__)						\
  p (RBP, rbp, ##__VA_ARGS__)						\
  p (R8, r8, ##__VA_ARGS__)						\
  p (R9, r9, ##__VA_ARGS__)						\
  p (R10, r10, ##__VA_ARGS__)						\
  p (R11, r11, ##__VA_ARGS__)						\
  p (R12, r12, ##__VA_ARGS__)						\
  p (R13, r13, ##__VA_ARGS__)						\
  p (R14, r14, ##__VA_ARGS__)						\
  p (R15, r15, ##__VA_ARGS__)

#define ERI_FOREACH_GPREG(p, ...) \
  ERI_FOREACH_GPREG_NO_RBX_RSP (p, ##__VA_ARGS__)			\
  p (RBX, rbx, ##__VA_ARGS__)						\
  p (RSP, rsp, ##__VA_ARGS__)

#define ERI_FOREACH_REG(p, ...) \
  ERI_FOREACH_GPREG (p, ##__VA_ARGS__)	/* keep gpregs first */		\
  p (RFLAGS, rflags, ##__VA_ARGS__)					\
  p (RIP, rip, ##__VA_ARGS__)

#ifndef __ASSEMBLER__

struct eri_registers
{
#define _ERI_DECLARE_REG(creg, reg)	uint64_t reg;
  ERI_FOREACH_REG (_ERI_DECLARE_REG)
};

#endif

#endif
