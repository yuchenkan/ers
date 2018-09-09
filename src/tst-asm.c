#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/syscall.h>

#include "recorder.h"

static struct ers_recorder *recorder;

struct ers_recorder *
ers_get_recorder (void)
{
  return recorder;
}

#define CAT_I(x, y) x##y
#define CAT(x, y) CAT_I (x, y)

#define REG_rax 0
#define REG_rdx 1
#define REG_rcx 2
#define REG_rbx 3
#define REG_rsi 4
#define REG_rdi 5
#define REG_rbp 6
#define REG_rsp 7
#define REG_r8 8
#define REG_r9 9
#define REG_r10 10
#define REG_r11 11
#define REG_r12 12
#define REG_r13 13
#define REG_r14 14
#define REG_r15 15

#define PP_IF_0(...)
#define PP_IF_1(...) __VA_ARGS__
#define PP_IF_I(c, ...) PP_IF_##c (__VA_ARGS__)
#define PP_IF(c, ...) PP_IF_I (c, ##__VA_ARGS__)

#define PP_IIF_0(t, f) f
#define PP_IIF_1(t, f) t
#define PP_IIF_I(c, t, f) PP_IIF_##c (t, f)
#define PP_IIF(c, t, f) PP_IIF_I (c, t, f)

#define PP_NE_CK_NIL 1
#define PP_NE_CKPP_NE_0(c, y) 0
#define PP_NE_CKPP_NE_1(c, y) 0
#define PP_NE_CKPP_NE_2(c, y) 0
#define PP_NE_CKPP_NE_3(c, y) 0
#define PP_NE_CKPP_NE_4(c, y) 0
#define PP_NE_CKPP_NE_5(c, y) 0
#define PP_NE_CKPP_NE_6(c, y) 0
#define PP_NE_CKPP_NE_7(c, y) 0
#define PP_NE_CKPP_NE_8(c, y) 0
#define PP_NE_CKPP_NE_9(c, y) 0
#define PP_NE_CKPP_NE_10(c, y) 0
#define PP_NE_CKPP_NE_11(c, y) 0
#define PP_NE_CKPP_NE_12(c, y) 0
#define PP_NE_CKPP_NE_13(c, y) 0
#define PP_NE_CKPP_NE_14(c, y) 0
#define PP_NE_CKPP_NE_15(c, y) 0

#define PP_NE_0(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_1(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_2(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_3(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_4(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_5(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_6(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_7(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_8(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_9(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_10(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_11(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_12(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_13(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_14(c, y) PP_IIF (c, _NIL, y (1, 0))
#define PP_NE_15(c, y) PP_IIF (c, _NIL, y (1, 0))

#define PP_NE_I(x, y) CAT (PP_NE_CK, PP_NE_##x (0, PP_NE_##y))
#define PP_NE(x, y) PP_NE_I (x, y)

#define PP_COMPL_0 1
#define PP_COMPL_1 0
#define PP_COMPL_I(x) PP_COMPL_##x
#define PP_COMPL(x) PP_COMPL_I (x)

#define PP_EQ(x, y) PP_COMPL (PP_NE (x, y))

#define PP_AND_0_0 0
#define PP_AND_0_1 0
#define PP_AND_1_0 0
#define PP_AND_1_1 0
#define PP_AND_I(x, y) PP_AND_##x_##y
#define PP_AND(x, y) PP_AND_I (x, y)

#define FOR_ALL(op, ...) \
  op (rax, ##__VA_ARGS__)	\
  op (rdx, ##__VA_ARGS__)	\
  op (rcx, ##__VA_ARGS__)	\
  op (rbx, ##__VA_ARGS__)	\
  op (rsi, ##__VA_ARGS__)	\
  op (rdi, ##__VA_ARGS__)	\
  op (rbp, ##__VA_ARGS__)	\
  op (rsp, ##__VA_ARGS__)	\
  op (r8, ##__VA_ARGS__)	\
  op (r9, ##__VA_ARGS__)	\
  op (r10, ##__VA_ARGS__)	\
  op (r11, ##__VA_ARGS__)	\
  op (r12, ##__VA_ARGS__)	\
  op (r13, ##__VA_ARGS__)	\
  op (r14, ##__VA_ARGS__)	\
  op (r15, ##__VA_ARGS__)

#define RFOR_ALL(op, ...) \
  op (r15, ##__VA_ARGS__)	\
  op (r14, ##__VA_ARGS__)	\
  op (r13, ##__VA_ARGS__)	\
  op (r12, ##__VA_ARGS__)	\
  op (r11, ##__VA_ARGS__)	\
  op (r10, ##__VA_ARGS__)	\
  op (r9, ##__VA_ARGS__)	\
  op (r8, ##__VA_ARGS__)	\
  op (rsp, ##__VA_ARGS__)	\
  op (rbp, ##__VA_ARGS__)	\
  op (rdi, ##__VA_ARGS__)	\
  op (rsi, ##__VA_ARGS__)	\
  op (rbx, ##__VA_ARGS__)	\
  op (rcx, ##__VA_ARGS__)	\
  op (rdx, ##__VA_ARGS__)	\
  op (rax, ##__VA_ARGS__)

#define SAVE(reg) \
  leaq	-8(%rsp), %rsp;			\
  .cfi_adjust_cfa_offset 8;		\
  movq	%reg, (%rsp);			\
  PP_IF (PP_NE (REG_##reg, REG_rsp), .cfi_rel_offset REG_##reg, 0;)	\

#define SAVE_ALL_REGS \
  _ERS_ASM_PUSH_FRAME (ERS_NONE, 20)	\
  FOR_ALL (SAVE)
#define SSAVE_ALL_REGS _ERS_STR (SAVE_ALL_REGS)

#define ASSERT(cc) \
  j##cc	1f;		\
  movq	$0, %rax;	\
  movq	$0, (%rax);	\
1:

#define ASSERT_NE ASSERT (ne)
#define SASSERT_NE _ERS_STR (ASSERT_NE)

#define ASSERT_EQ ASSERT (e)
#define SASSERT_EQ _ERS_STR (ASSERT_EQ)

#define CHECK(reg) \
  cmpq	%reg, (%rsp);			\
  ASSERT_EQ				\
  addq	$8, %rsp;			\
  .cfi_adjust_cfa_offset -8;		\
  .cfi_restore REG_##reg;		\

#define CHECK_ALL_REGS \
  RFOR_ALL (CHECK)		\
  _ERS_ASM_POP_FRAME (ERS_NONE, 0)
#define SCHECK_ALL_REGS _ERS_STR (CHECK_ALL_REGS)

#define START_TST(name) \
  .text;				\
  .type tst_##name, @function;		\
tst_##name:				\
  .cfi_startproc;			\
  pushq	%rbx;				\
  .cfi_adjust_cfa_offset 8;		\
  .cfi_rel_offset %rbx, 0;		\
  pushq	%r12;				\
  .cfi_adjust_cfa_offset 8;		\
  .cfi_rel_offset %r12, 0;		\
  pushq	%r13;				\
  .cfi_adjust_cfa_offset 8;		\
  .cfi_rel_offset %r13, 0;
#define SSTART_TST(name) _ERS_STR (START_TST (name))

#define END_TST(name) \
  .cfi_def_cfa_register %rsp;		\
  popq	%r13;				\
  .cfi_adjust_cfa_offset -8;		\
  .cfi_restore %r13;			\
  popq	%r12;				\
  .cfi_adjust_cfa_offset -8;		\
  .cfi_restore %r12;			\
  popq	%rbx;				\
  .cfi_adjust_cfa_offset -8;		\
  .cfi_restore %rbx;			\
  ret;					\
  .cfi_endproc;				\
  .size tst_##name, .-tst_##name;	\
  .previous;
#define SEND_TST(name) _ERS_STR (END_TST (name))

#define DECLARE_TST(name) \
void tst_##name (int *a1, int *a2, int *a3, int *a4, int *a5, int *a6);

#define INC_IF_EQ(m) \
  jne	1f;		\
  incl	m;		\
1:

#define CMPL(ir, m) \
  pushfq;		\
  .cfi_adjust_cfa_offset 8;	\
  ERS_ASM_CMPL (ir, m)	\
  INC_IF_EQ (m)			\
  popfq;			\
  .cfi_adjust_cfa_offset -8;
#define SCMPL(ir, m) _ERS_STR (CMPL (ir, m))

asm (SSTART_TST (cmpli) "	\n\
  movq	%rcx, %rbx		\n\
  movq	%r8, %r12		\n\
  movq	%r9, %r13		\n\
  " SSAVE_ALL_REGS "		\n\
  leaq	-128(%rsp), %rsp	\n\
  .cfi_adjust_cfa_offset 128	\n\
  " SCMPL ($0, (%rdi)) "	\n\
  " SCMPL ($0, (%rsi)) "	\n\
  " SCMPL ($0, (%rdx)) "	\n\
  " SCMPL ($0, (%rcx)) "	\n\
  " SCMPL ($0, (%r8)) "		\n\
  " SCMPL ($0, (%r9)) "		\n\
  " SCMPL ($0, (%rbx)) "	\n\
  " SCMPL ($0, (%r12)) "	\n\
  " SCMPL ($0, (%r13)) "	\n\
  leaq	128(%rsp), %rsp		\n\
  .cfi_adjust_cfa_offset -128	\n\
  " SCHECK_ALL_REGS "		\n\
  " SEND_TST (cmpli)
);

DECLARE_TST (cmpli)

asm (SSTART_TST (cmplr) "	\n\
  movq	%rcx, %rbx		\n\
  movl	$0, %eax		\n\
  movl	$0, %r12d		\n\
  movl	$0, %r13d		\n\
  " SSAVE_ALL_REGS "		\n\
  leaq	-128(%rsp), %rsp	\n\
  .cfi_adjust_cfa_offset 128	\n\
  " SCMPL (%eax, (%rdi)) "	\n\
  " SCMPL (%eax, (%rsi)) "	\n\
  " SCMPL (%eax, (%rdx)) "	\n\
  " SCMPL (%eax, (%rcx)) "	\n\
  " SCMPL (%eax, (%r8)) "	\n\
  " SCMPL (%eax, (%r9)) "	\n\
  " SCMPL (%eax, (%rbx)) "	\n\
  " SCMPL (%r12d, (%rbx)) "	\n\
  " SCMPL (%r13d, (%rbx)) "	\n\
  leaq	128(%rsp), %rsp		\n\
  .cfi_adjust_cfa_offset -128	\n\
  " SCHECK_ALL_REGS "		\n\
  " SEND_TST (cmplr)
);

DECLARE_TST (cmplr)

#define SAVE_FLAGS \
  pushq	%r12;			\
  .cfi_adjust_cfa_offset 8;	\
  pushq	%r13;			\
  .cfi_adjust_cfa_offset 8;	\
  pushfq;			\
  .cfi_adjust_cfa_offset 8;
#define SSAVE_FLAGS _ERS_STR (SAVE_FLAGS)

#define CHECK_FLAGS \
  popq	%r13;			\
  .cfi_adjust_cfa_offset -8;	\
  pushfq;			\
  .cfi_adjust_cfa_offset 8;	\
  popq	%r12;			\
  .cfi_adjust_cfa_offset -8;	\
  andq	$0x8d5, %r12;		\
  andq	$0x8d5, %r13;		\
  cmpq	%r12, %r13;		\
  ASSERT_EQ			\
  popq	%r13;			\
  .cfi_adjust_cfa_offset -8;	\
  popq	%r12;			\
  .cfi_adjust_cfa_offset -8;
#define SCHECK_FLAGS _ERS_STR (CHECK_FLAGS)

asm (SSTART_TST (movl_sv) "		\n\
  movl	$0, %eax			\n\
  movl	$0, %r12d			\n\
  movl	$0, %r13d			\n\
  " SSAVE_ALL_REGS "			\n\
  " SSAVE_FLAGS "			\n\
  " ERS_ASM_SMOVL_SV ($0, (%rdi)) "	\n\
  " ERS_ASM_SMOVL_SV (%eax, (%rsi)) "	\n\
  " ERS_ASM_SMOVL_SV (%r12d, (%rdx)) "	\n\
  " ERS_ASM_SMOVL_SV (%r13d, (%rcx)) "	\n\
  " SCHECK_FLAGS "			\n\
  " SCHECK_ALL_REGS "			\n\
  " SEND_TST (movl_sv)
);

DECLARE_TST (movl_sv)

#define MOVL_LD(m, r, v) \
  ERS_ASM_MOVL_LD (m, r)	\
  pushfq;			\
  .cfi_adjust_cfa_offset 8;	\
  cmpl	v, r;			\
  ASSERT_EQ			\
  popfq;			\
  .cfi_adjust_cfa_offset -8;
#define SMOVL_LD(m, r, v) _ERS_STR (MOVL_LD (m, r, v))

asm (SSTART_TST (movl_ld) "		\n\
  movq	%rcx, %rbx			\n\
  movq	%r8, %r12			\n\
  movq	%r9, %r13			\n\
  " SSAVE_ALL_REGS "			\n\
  " SSAVE_FLAGS "			\n\
  pushq	%rax				\n\
  .cfi_adjust_cfa_offset 8		\n\
  " SMOVL_LD ((%rdi), %eax, $0) "	\n\
  " SMOVL_LD ((%rsi), %eax, $0) "	\n\
  " SMOVL_LD ((%rdx), %eax, $0) "	\n\
  " SMOVL_LD ((%rcx), %eax, $0) "	\n\
  " SMOVL_LD ((%r8), %eax, $0) "	\n\
  " SMOVL_LD ((%r9), %eax, $0) "	\n\
  " SMOVL_LD ((%rbx), %eax, $0) "	\n\
  " SMOVL_LD ((%r12), %eax, $0) "	\n\
  " SMOVL_LD ((%r13), %eax, $0) "	\n\
  popq	%rax				\n\
  .cfi_adjust_cfa_offset -8		\n\
  " SCHECK_FLAGS "			\n\
  " SCHECK_ALL_REGS "			\n\
  " SEND_TST (movl_ld)
);

DECLARE_TST (movl_ld)

asm (SSTART_TST (decl) "		\n\
  movq	%rcx, %rbx			\n\
  movq	%r8, %r12			\n\
  movq	%r9, %r13			\n\
  " SSAVE_ALL_REGS "			\n\
  pushq	%rbp				\n\
  .cfi_adjust_cfa_offset 8		\n\
  .cfi_rel_offset %rbp, 0		\n\
  movq	%rsp, %rbp			\n\
  .cfi_def_cfa_register %rbp		\n\
  " ERS_ASM_SDECL (lock, (%rdi)) "	\n\
  " ERS_ASM_SDECL (lock, (%rsi)) "	\n\
  " ERS_ASM_SDECL (lock, (%rdx)) "	\n\
  " ERS_ASM_SDECL (lock, (%rcx)) "	\n\
  " ERS_ASM_SDECL (lock, (%r8)) "	\n\
  " ERS_ASM_SDECL (lock, (%r9)) "	\n\
  " ERS_ASM_SDECL (lock, (%rbx)) "	\n\
  " ERS_ASM_SDECL (lock, (%r12)) "	\n\
  " ERS_ASM_SDECL (lock, (%r13)) "	\n\
  leave					\n\
  .cfi_def_cfa_register %rsp		\n\
  .cfi_restore %rbp			\n\
  .cfi_adjust_cfa_offset -8		\n\
  " SCHECK_ALL_REGS "			\n\
  " SEND_TST (decl)
);

DECLARE_TST (decl)

#define XCHGL(r, m, mv, rv) \
  movl	rv, r;			\
  ERS_ASM_XCHGL (r, m)		\
  pushfq;			\
  .cfi_adjust_cfa_offset 8;	\
  cmpl	mv, r;			\
  ASSERT_EQ			\
  cmpl	rv, m;			\
  ASSERT_EQ			\
  popfq;			\
  .cfi_adjust_cfa_offset -8;
#define SXCHGL(r, m, mv, rv) _ERS_STR (XCHGL (r, m, mv, rv))

asm (SSTART_TST (xchgl) "		\n\
  movq	%rcx, %rbx			\n\
  movq	%r8, %r12			\n\
  movq	%r9, %r13			\n\
  " SSAVE_ALL_REGS "			\n\
  " SSAVE_FLAGS "			\n\
  pushq	%rax				\n\
  .cfi_adjust_cfa_offset 8		\n\
  " SXCHGL (%eax, (%rdi), $1, $0) "	\n\
  " SXCHGL (%eax, (%rsi), $1, $0) "	\n\
  " SXCHGL (%eax, (%rdx), $1, $0) "	\n\
  " SXCHGL (%eax, (%rcx), $1, $0) "	\n\
  " SXCHGL (%eax, (%r8), $1, $0) "	\n\
  " SXCHGL (%eax, (%r9), $1, $0) "	\n\
  " SXCHGL (%eax, (%rbx), $0, $2) "	\n\
  " SXCHGL (%eax, (%r12), $0, $2) "	\n\
  " SXCHGL (%eax, (%r13), $0, $2) "	\n\
  popq	%rax				\n\
  .cfi_adjust_cfa_offset -8		\n\
  " SCHECK_FLAGS "			\n\
  " SCHECK_ALL_REGS "			\n\
  " SEND_TST (xchgl)
);

DECLARE_TST (xchgl)

asm (SSTART_TST (cmpxchgl) "			\n\
  movq	%rsi, %rbx				\n\
  movq	%rdx, %r12				\n\
  " SSAVE_ALL_REGS "				\n\
  pushq	%rax					\n\
  .cfi_adjust_cfa_offset 8			\n\
  pushq	%r13					\n\
  .cfi_adjust_cfa_offset 8			\n\
  movl	$1, %eax				\n\
  movl	$2, %r13d				\n\
  " ERS_ASM_SCMPXCHGL (lock, %r13d, (%rdi)) "	\n\
  " SASSERT_NE "				\n\
  cmpl	$0, %eax				\n\
  " SASSERT_EQ "				\n\
  cmpl	$2, %r13d				\n\
  " SASSERT_EQ "				\n\
  cmpl	$0, (%rdi)				\n\
  " SASSERT_EQ "				\n\
  movl	$1, %eax				\n\
  movl	$2, %r13d				\n\
  " ERS_ASM_SCMPXCHGL (lock, %r13d, (%rbx)) "	\n\
  " SASSERT_EQ "				\n\
  cmpl	$1, %eax				\n\
  " SASSERT_EQ "				\n\
  cmpl	$2, %r13d				\n\
  " SASSERT_EQ "				\n\
  cmpl	$2, (%rbx)				\n\
  " SASSERT_EQ "				\n\
  movl	$1, %eax				\n\
  movl	$2, %r13d				\n\
  " ERS_ASM_SCMPXCHGL (lock, %r13d, (%r12)) "	\n\
  " SASSERT_EQ "				\n\
  cmpl	$1, %eax				\n\
  " SASSERT_EQ "				\n\
  cmpl	$2, %r13d				\n\
  " SASSERT_EQ "				\n\
  cmpl	$2, (%r12)				\n\
  " SASSERT_EQ "				\n\
  popq	%r13					\n\
  .cfi_adjust_cfa_offset -8			\n\
  popq	%rax					\n\
  .cfi_adjust_cfa_offset -8			\n\
  " SCHECK_ALL_REGS "				\n\
  " SEND_TST (cmpxchgl)
);

DECLARE_TST (cmpxchgl)

#define SAVE_SYSCALL_REGS \
  SAVE_ALL_REGS					\
  pushq	%rax;					\
  .cfi_adjust_cfa_offset 8;			\
  pushq	%rcx;					\
  .cfi_adjust_cfa_offset 8;			\
  pushq	%r11;					\
  .cfi_adjust_cfa_offset 8;
#define SSAVE_SYSCALL_REGS _ERS_STR (SAVE_SYSCALL_REGS)

#define CHECK_SYSCALL_REGS \
  popq	%r11;					\
  .cfi_adjust_cfa_offset -8;			\
  popq	%rcx;					\
  .cfi_adjust_cfa_offset -8;			\
  popq	%rax;					\
  .cfi_adjust_cfa_offset -8;			\
  CHECK_ALL_REGS
#define SCHECK_SYSCALL_REGS _ERS_STR (CHECK_SYSCALL_REGS)

asm ("  .text					\n\
  .type tst_syscall, @function			\n\
tst_syscall:					\n\
  .cfi_startproc				\n\
  " SSAVE_SYSCALL_REGS "			\n\
  movl	$" _ERS_STR (__NR_gettid) ", %eax	\n\
  " _ERS_STR (ERS_ASM_SYSCALL) "		\n\
  movq	%rax, (%rdi)				\n\
  " SCHECK_SYSCALL_REGS "			\n\
  ret						\n\
  .cfi_endproc					\n\
  .size tst_syscall, .-tst_syscall		\n\
  .previous					\n"
);

void tst_syscall (long *t);

void tst ()
{
  int i;

  int a1[6] = { 0, 0, 0, 1, 1, 1 };
  asm ("xor %%rax, %%rax; cmpl $1, %%eax;" ::: "rax");
  tst_cmpli (a1 + 0, a1 + 1, a1 + 2, a1 + 3, a1 + 4, a1 + 5);
  for (i = 0; i < 6; ++i) assert (a1[i] == 1);

  int a2[6] = { 1, 1, 1 };
  asm ("xor %%rax, %%rax; cmpl $0, %%eax;" ::: "rax");
  tst_cmpli (a2 + 0, a2 + 1, a2 + 2, a2 + 3, a2 + 4, a2 + 5);
  for (i = 0; i < 6; ++i) assert (a2[i] == 1);

  int a3[6] = { 0, 0, 0, 1, 1, 1 };
  asm ("xor %%rax, %%rax; cmpl $1, %%eax;" ::: "rax");
  tst_cmplr (a3 + 0, a3 + 1, a3 + 2, a3 + 3, a3 + 4, a3 + 5);
  for (i = 0; i < 6; ++i) assert (a3[i] == 1);

  int b[4] = { 1, 1, 1, 1 };
  asm ("xor %%rax, %%rax; cmpl $1, %%eax;" ::: "rax");
  tst_movl_sv (b + 0, b + 1, b + 2, b + 3, (int *) 123, (int *) 456);
  for (i = 0; i < 4; ++i) assert (b[i] == 0);

  int c[6] = { 0 };
  asm ("xor %%rax, %%rax; cmpl $0, %%eax;" ::: "rax");
  tst_movl_ld (c + 0, c + 1, c + 2, c + 3, c + 4, c + 5);

  int d = 9;
  tst_decl (&d, &d, &d, &d, &d, &d);
  assert (d == 0);

  int e[6] = { 1, 1, 1, 1, 1, 1 };
  asm ("xor %%rax, %%rax; cmpl $1, %%eax;" ::: "rax");
  tst_xchgl (e + 0, e + 1, e + 2, e + 3, e + 4, e + 5);

  int f[3] = { 0, 1, 1 };
  asm ("xor %%rax, %%rax; cmpl $1, %%eax;" ::: "rax");
  tst_cmpxchgl (f + 0, f + 1, f + 2, (int *) 123, (int *) 456, (int *) 789);

  long tid;
  tst_syscall (&tid);
  printf ("tid %ld\n", tid);
  assert (tid == syscall (SYS_gettid));
}

#define SYSCALL(nr, a1, a3, a4, a5, a6, ret) \
  cmpl	CAT_I ($, nr), %eax;			\
  ASSERT_EQ					\
  cmpq	CAT_I ($, a1), %rdi;			\
  ASSERT_EQ					\
  cmpq	CAT_I ($, a3), %rdx;			\
  ASSERT_EQ					\
  cmpq	CAT_I ($, a4), %r10;			\
  ASSERT_EQ					\
  cmpq	CAT_I ($, a5), %r8;			\
  ASSERT_EQ					\
  cmpq	CAT_I ($, a6), %r9;			\
  ASSERT_EQ					\
  movq	CAT_I ($, ret), %rax;

#define syscall SYSCALL (__NR_clone, 1, 3, 4, 5, 6, 7)

asm ("  .text					\n\
  .type tst_clone, @function			\n\
tst_clone:					\n\
  .cfi_startproc				\n\
  subq	$264, %rsp				\n\
  .cfi_adjust_cfa_offset 264			\n\
  movq	$1, %rdi				\n\
  leaq	256(%rsp), %rsi				\n\
  movq	$3, %rdx				\n\
  movq	$4, %r10				\n\
  movq	$5, %r8					\n\
  movq	$6, %r9					\n\
  " SSAVE_SYSCALL_REGS "			\n\
  movq	%rsp, (%rsi)				\n\
  movl	$" _ERS_STR (__NR_clone) ", %eax	\n\
  .cfi_endproc					\n\
  " _ERS_STR (ERS_ASM_CLONE) "			\n\
  .cfi_startproc				\n\
  .cfi_undefined %rip				\n\
  testq	%rax, %rax				\n\
  jnz	1f					\n\
  popq	%rsp					\n\
1:						\n\
  movq	%rax, (%rsi)				\n\
  .cfi_remember_state				\n\
  " SCHECK_SYSCALL_REGS "			\n\
  addq	$256, %rsp				\n\
  popq	%rax					\n\
  ret						\n\
  .cfi_endproc					\n\
  .size tst_clone, .-tst_clone			\n\
  .previous					\n"
);

#undef syscall

long tst_clone ();

#define CHECK_CLONE \
  assert (nr == __NR_clone && a1 == 1 && a3 == 3	\
	  && a4 == 4 && a5 == 5 && a6 == 6)

static char
syscall_clone1 (int nr, long a1, long a2, long a3,
		long a4, long a5, long a6, long *res)
{
  CHECK_CLONE;
  return 0;
}

static char
syscall_clone2 (int nr, long a1, long a2, long a3,
		long a4, long a5, long a6, long *res)
{
  CHECK_CLONE;
  *res = 1;
  return 1;
}

asm ("  .text					\n\
  .type syscall_clone3, @function		\n\
syscall_clone3:					\n\
  .cfi_startproc				\n\
  .cfi_undefined %rip				\n\
  subq	$8, %rdx				\n\
  movq	(%rsp), %rax				\n\
  movq	%rax, (%rdx)				\n\
  movq	%rdx, %rsp				\n\
  movb	$2, %al					\n\
  ret						\n\
  .cfi_endproc					\n\
  .size syscall_clone3, .-syscall_clone3	\n\
  .previous					\n"
);

char
syscall_clone3 (int nr, long a1, long a2, long a3,
		long a4, long a5, long a6, long *res);

struct ers_recorder *eri_get_recorder (void);

int main ()
{
  struct ers_recorder clone1 = { 0, 0, syscall_clone1 };
  struct ers_recorder clone2 = { 0, 0, syscall_clone2 };
  struct ers_recorder clone3 = { 0, 0, syscall_clone3 };

  assert (tst_clone () == 7);

  recorder = &clone1;
  assert (tst_clone () == 7);

  recorder = &clone2;
  assert (tst_clone () == 1);

  recorder = &clone3;
  assert (tst_clone () == 0);

  recorder = NULL;
  tst ();

  recorder = eri_get_recorder ();

  tst ();

  recorder->init_process ("ers_data");

  tst ();

  recorder->syscall (__NR_exit, 0, 0, 0, 0, 0, 0, NULL);
  __builtin_unreachable ();
}
