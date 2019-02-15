/* vim: set ft=gas: */

#include <public/common.h>
#include <lib/util.h>
#include <lib/syscall.h>

#include <live-thread-local-offsets.h>
#include <lib/syscall-offsets.h>

#define PASTE		ERI_PASTE

#define R0_b(i)		PASTE (i, l)
#define R0_w(i)		PASTE (i, x)
#define R0_l(i)		PASTE (e, i, x)
#define R0_q(i)		PASTE (r, i, x)

#define RAX(sz)		PASTE (R0_, sz) (a)
#define RBX(sz)		PASTE (R0_, sz) (b)
#define RDX(sz)		PASTE (R0_, sz) (d)
#define RCX(sz)		PASTE (R0_, sz) (c)

#define R1_b(i)		PASTE (i, l)
#define R1_w(i)		i
#define R1_l(i)		PASTE (e, i)
#define R1_q(i)		PASTE (r, i)

#define RDI(sz)		PASTE (R1_, sz) (di)
#define RSI(sz)		PASTE (R1_, sz) (si)
#define RSP(sz)		PASTE (R1_, sz) (sp)
#define RBP(sz)		PASTE (R1_, sz) (bp)

#define R2_b(i)		PASTE (i, b)
#define R2_w(i)		PASTE (i, w)
#define R2_l(i)		PASTE (i, d)
#define R2_q(i)		i

#define R8(sz)		PASTE (R2_, sz) (r8)
#define R9(sz)		PASTE (R2_, sz) (r9)
#define R10(sz)		PASTE (R2_, sz) (r10)
#define R11(sz)		PASTE (R2_, sz) (r11)
#define R12(sz)		PASTE (R2_, sz) (r12)
#define R13(sz)		PASTE (R2_, sz) (r13)
#define R14(sz)		PASTE (R2_, sz) (r14)
#define R15(sz)		PASTE (R2_, sz) (r15)


#define TC(name)	PASTE (THREAD_CONTEXT_, name)
#define TCE(name)	TC (PASTE (EXT_, name))

  .data

/************************************************/
/* thread_context_text				*/
/************************************************/

  .align 16
ERI_SYMBOL (thread_context_text)
#define RIP_RELA(off)	thread_context_text - TC (SIZE16) + off(%rip)

ERI_SYMBOL (thread_context_text_entry)
  leaq	RIP_RELA (0), %rbx
  jmp	*RIP_RELA (TC (ENTRY))

  .align 16
ERI_SYMBOL (thread_context_text_return)
  movq	RIP_RELA (TCE (RBX)), %rbx
  jmp	*RIP_RELA (TCE (RET))

ERI_SYMBOL (thread_context_text_end)

  .text

#define LABEL(name)			PASTE (.L, name)

#define FOREACH_SGREG_NO_RCX_RDX(p, ...) \
  p (RAX, rax, ##__VA_ARGS__);						\
  p (RDI, rdi, ##__VA_ARGS__);						\
  p (RSI, rsi, ##__VA_ARGS__);						\
  p (R8, r8, ##__VA_ARGS__);						\
  p (R9, r9, ##__VA_ARGS__);						\
  p (R10, r10, ##__VA_ARGS__);						\
  p (R11, r11, ##__VA_ARGS__)

#define FOREACH_SGREG_NO_RCX(p, ...) \
  FOREACH_SGREG_NO_RCX_RDX (p, ##__VA_ARGS__);				\
  p (RDX, rdx, ##__VA_ARGS__)

#define FOREACH_EREG(p, ...) \
  p (RBP, rbp, ##__VA_ARGS__);						\
  p (R12, r12, ##__VA_ARGS__);						\
  p (R13, r13, ##__VA_ARGS__);						\
  p (R14, r14, ##__VA_ARGS__);						\
  p (R15, r15, ##__VA_ARGS__)

#define TH_CALL(fn) \
  movq	TC (TH)(%rbx), %rdi;						\
  call	fn

/************************************************/
/* sig_return					*/
/************************************************/

/* Registers except rcx rbx rip should be restored before SIG_RETURN  */
#define SIG_RETURN(sig_hand, sig_return) \
  movb	$PASTE (SIG_HAND_, sig_hand), TCE (OP_SIG_HAND)(%rbx);		\
  /* sig_frame is set to 1 when null.  */				\
  movq	TC (SIG_FRAME)(%rbx), %rcx;					\
  loop	sig_return;							\
									\
  movq	TC (SREGS_RCX)(%rbx), %rcx;					\
  jmp	*TC (RET)(%rbx)

#define SIG_SAVE_CTX_REG(creg, reg, frame) \
  movq	%reg, ERI_PASTE (ERI_SIGFRAME_CTX_MCTX_, creg)(frame)

#define SIG_RETURN_ACTION(action) \
  FOREACH_SGREG_NO_RCX (SIG_SAVE_CTX_REG, %rcx);			\
  ERI_MOV_MM (TCE (RBX)(%rbx),						\
	      ERI_SIGFRAME_CTX_MCTX_RBX(%rcx), %rax);			\
  ERI_MOV_MM (TCE (RET)(%rbx),						\
	      ERI_SIGFRAME_CTX_MCTX_RIP(%rcx), %rax);			\
  SIG_SAVE_CTX_REG (RSP, rsp, %rcx);					\
  ERI_MOV_MM (TC (SREGS_RCX)(%rbx),					\
	      ERI_SIGFRAME_CTX_MCTX_RCX(%rcx), %rax);			\
  movq	TC (TOP)(%rbx), %rsp;						\
  pushfq;								\
  popq	ERI_SIGFRAME_CTX_MCTX_RFLAGS(%rcx);				\
  FOREACH_EREG (SIG_SAVE_CTX_REG, %rcx);				\
  TH_CALL (action)

#define SIG_RETURN_TO_USER(label) \
  SIG_RETURN (RETURN_TO_USER, label);					\
label:									\
  SIG_RETURN_ACTION (sig_action)

/************************************************/
/* main						*/
/************************************************/

ERI_FUNCTION (main)
  movq	%rdi, %rbx
  TH_CALL (start_main)

  movq	$0, TCE (RBX)(%rbx)
  movq	$0, TC (SREGS_RCX)(%rbx)

#define ZERO_REG(creg, reg) \
  xorq	%reg, %reg

  FOREACH_SGREG_NO_RCX_RDX (ZERO_REG)
  FOREACH_EREG (ZERO_REG)

  movq	TC (SREGS_RDX)(%rbx), %rdx
  pushq	$0
  popfq
  movq	TC (RSP)(%rbx), %rsp

  SIG_RETURN_TO_USER (.lmain_sig_return)

  ERI_END_FUNCTION (main)

/************************************************/
/* entry					*/
/************************************************/

#define ERROR_OP_CODE		0
#define ERROR_ATOMIC_SIZE	1

#define ERROR(code) \
  movq	PASTE (ERROR_, code), %r14;					\
  jmp	.lerror

ERI_FUNCTION (entry)

  movq	%rsp, TC (RSP)(%rbx)
  movq	TC (TOP)(%rbx), %rsp

  pushfq
  popq	TC (SREGS_RFLAGS)(%rbx)

  pushq	$0
  popfq

  movq	%rax, TC (SREGS_RAX)(%rbx)
  movq	%rdi, TC (SREGS_RDI)(%rbx)
  movq	%rsi, TC (SREGS_RSI)(%rbx)
  movq	%rdx, TC (SREGS_RDX)(%rbx)
  movq	%rcx, TC (SREGS_RCX)(%rbx)
  movq	%r8, TC (SREGS_R8)(%rbx)
  movq	%r9, TC (SREGS_R9)(%rbx)
  movq	%r10, TC (SREGS_R10)(%rbx)
  movq	%r11, TC (SREGS_R11)(%rbx)

#define RESTORE_SGREG(creg, reg) \
  movq	TC (PASTE (SREGS_, creg))(%rbx), %reg				\

#define RESTORE_NO_RCX \
  FOREACH_SGREG_NO_RCX (RESTORE_SGREG);					\
  pushq	TC (SREGS_RFLAGS)(%rbx);					\
  popfq;								\
  movq	TC (RSP)(%rbx), %rsp

#define RESTORE \
  RESTORE_SGREG (RCX, rcx);						\
  RESTORE_NO_RCX

  movw	TCE (OP_CODE)(%rbx), %r11w

  cmpw	$_ERS_OP_SYSCALL, %r11w
  je	.lsyscall

  cmpw	$_ERS_OP_SYNC_ASYNC, %r11w
  je	.lsync_async

#define ATOMIC_LABEL(name)	LABEL (PASTE (atomic_, name))

/* %r11w is op.  */
#define IF_ATOMIC(cname, name) \
  cmpw	$PASTE (_ERS_OP_ATOMIC_, cname), %r11w;				\
  je	ATOMIC_LABEL (name)

  IF_ATOMIC (LOAD, load)
  IF_ATOMIC (STORE, store)
  IF_ATOMIC (INC, inc)
  IF_ATOMIC (DEC, dec)
  IF_ATOMIC (XCHG, xchg)
  IF_ATOMIC (CMPXCHG, cmpxchg)

  ERROR (OP_CODE)

/************************************************/
/* entry: syscall				*/
/************************************************/

.lsyscall:
  cmpl	$__NR_clone, %eax
  je	.lsyscall_extra_save
  cmpl	$__NR_rt_sigreturn, %eax
  je	.lsyscall_extra_save
  jmp	.lsyscall_no_extra_save

.lsyscall_extra_save:

#define SYSCALL_SAVE_EREG(creg, reg) \
  movq	%reg, TC (PASTE (SYSCALL_EREGS_, creg))(%rbx)

  FOREACH_EREG (SYSCALL_SAVE_EREG)

.lsyscall_no_extra_save:
  TH_CALL (syscall)

  cmpl	$__NR_rt_sigreturn, %eax
  jne	.lsyscall_no_extra_restore

#define SYSCALL_RESTORE_EREG(creg, reg) \
  movq	TC (PASTE (SYSCALL_EREGS_, creg))(%rbx), %reg

  FOREACH_EREG (SYSCALL_RESTORE_EREG)

.lsyscall_no_extra_restore:
  RESTORE_NO_RCX
  SIG_RETURN_TO_USER (.lsyscall_sig_return)

/************************************************/
/* entry: sync_async				*/
/************************************************/

.lsync_async:

  movq	%rcx, %rsi
  TH_CALL (sync_async)

  RESTORE_NO_RCX
  SIG_RETURN (SYNC_ASYNC_RETURN_TO_USER, .lsync_async_sig_return)

.lsync_async_sig_return:

  SIG_RETURN_ACTION (sig_restart_sync_async)

/************************************************/
/* entry: atomic_common				*/
/************************************************/

#define ATOMIC_SIZE_LABEL(sz, name)	ATOMIC_LABEL (PASTE (name, sz))
#define ATOMIC_ACCESS_START_LABEL(sz, name) \
  ATOMIC_SIZE_LABEL (sz, PASTE (name, _access_start))
#define ATOMIC_ACCESS_END_LABEL(sz, name) \
  ATOMIC_SIZE_LABEL (sz, PASTE (name, _access_end))

#define PREPARE_ATOMIC(sz, name) \
ATOMIC_SIZE_LABEL (sz, name):						\
  leaq	ATOMIC_ACCESS_START_LABEL (sz, name), %rsi;			\
  leaq	ATOMIC_ACCESS_END_LABEL (sz, name), %rdx;			\
  TH_CALL (prepare_atomic)

#define COMPLETE_ATOMIC(sz, name) \
  TH_CALL (complete_atomic);						\
									\
  RESTORE_NO_RCX;							\
  SIG_RETURN_TO_USER (ATOMIC_SIZE_LABEL (sz, PASTE (name, _sig_return)))

#define ATOMIC_LOAD_RFLAGS \
  pushq	TC (SREGS_RFLAGS)(%rbx);					\
  popfq

#define ATOMIC_SAVE_RFLAGS \
  pushfq;								\
  popq	TC (SREGS_RFLAGS)(%rbx)

/************************************************/
/* entry: atomic_ext_return			*/
/************************************************/

.latomic_ext_return:
  movq	%rcx, TC (SREGS_RCX)(%rbx)
  ERI_MOV_LM (entry, TCE (ENTRY), %rcx)
  ERI_MOV_MM (TCE (ATOMIC_RET)(%rbx), TCE (RET)(%rbx), %rcx)

  SIG_RETURN_TO_USER (.latomic_ext_return_sig_return)

#define EXT_COMPLETE_ATOMIC \
  TH_CALL (complete_atomic);						\
									\
  ERI_MOV_LM (.latomic_ext_return, TCE (ENTRY)(%rbx), %rax);		\
  RESTORE;								\
  jmp	*TC (RET)(%rbx)

/************************************************/
/* eri_live_entry: atomic_load			*/
/************************************************/

#define ATOMIC_LOAD(sz) \
PREPARE_ATOMIC (sz, load);						\
									\
ATOMIC_ACCESS_START_LABEL (sz, load):					\
  PASTE (mov, sz)	(%rax), %R11 (sz);				\
ATOMIC_ACCESS_END_LABEL (sz, load):					\
									\
  movq	%r11, TCE (ATOMIC_VAL)(%rbx);					\
  EXT_COMPLETE_ATOMIC

/************************************************/
/* eri_live_entry: atomic_store			*/
/************************************************/

#define ATOMIC_STORE(sz) \
PREPARE_ATOMIC (sz, store);						\
									\
  movq	TCE (ATOMIC_VAL)(%rbx), %r11;					\
ATOMIC_ACCESS_START_LABEL (sz, store):					\
  PASTE (mov, sz)	%R11 (sz), (%rax);				\
ATOMIC_ACCESS_END_LABEL (sz, store):					\
									\
  COMPLETE_ATOMIC (sz, store)

/************************************************/
/* eri_live_entry: atomic_inc / atomic_dec	*/
/************************************************/

#define ATOMIC_INC_DEC(sz, inc) \
PREPARE_ATOMIC (sz, inc);						\
									\
  ATOMIC_LOAD_RFLAGS;							\
ATOMIC_ACCESS_START_LABEL (sz, inc):					\
  PASTE (mov, sz)	(%rax), %R11 (sz);				\
  PASTE (inc, sz)	(%rax);						\
ATOMIC_ACCESS_END_LABEL (sz, inc):					\
									\
  ATOMIC_SAVE_RFLAGS;							\
  movq	%r11, TCE (ATOMIC_VAL)(%rbx);					\
  COMPLETE_ATOMIC (sz, inc)

#define ATOMIC_INC(sz)	ATOMIC_INC_DEC (sz, inc)
#define ATOMIC_DEC(sz)	ATOMIC_INC_DEC (sz, dec)

/************************************************/
/* eri_live_entry: atomic_xchg			*/
/************************************************/

#define ATOMIC_XCHG(sz) \
PREPARE_ATOMIC (sz, xchg);						\
									\
  movq	TCE (ATOMIC_VAL)(%rbx), %r11;					\
ATOMIC_ACCESS_START_LABEL (sz, xchg):					\
  PASTE (xchg, sz)	%R11 (sz), (%rax);				\
ATOMIC_ACCESS_END_LABEL (sz, xchg):					\
									\
  movq	%r11, TCE (ATOMIC_VAL)(%rbx);					\
  EXT_COMPLETE_ATOMIC

/************************************************/
/* eri_live_entry: atomic_cmpxchg		*/
/************************************************/

#define ATOMIC_CMPXCHG(sz) \
PREPARE_ATOMIC (sz, cmpxchg);						\
									\
  movq	TCE (ATOMIC_VAL)(%rbx), %r11;					\
  movq	%rax, %rdi;							\
  movq	TC (SREGS_RAX)(%rbx), %rax;					\
  ATOMIC_LOAD_RFLAGS;							\
ATOMIC_ACCESS_START_LABEL (sz, cmpxchg):				\
  PASTE (mov, sz)	(%rdi), %RSI (sz);				\
  PASTE (cmpxchg, sz)	%R11 (sz), (%rdi);				\
ATOMIC_ACCESS_END_LABEL (sz, cmpxchg):					\
									\
  ATOMIC_SAVE_RFLAGS;							\
  movq	%rax, TC (SREGS_RAX)(%rbx);					\
  movq	%rsi, TCE (ATOMIC_VAL)(%rbx);					\
  COMPLETE_ATOMIC (sz, cmpxchg)

/************************************************/
/* entry: atomic				*/
/************************************************/

#define IF_ATOMIC_SIZE(sz, name) \
  cmpb	$_ERS_ATOMIC_SIZE (sz), %r11b;					\
  je	ATOMIC_SIZE_LABEL (sz, name)

 #define ATOMIC_OP(cname) \
  PASTE (ATOMIC_, cname) (b);						\
  PASTE (ATOMIC_, cname) (w);						\
  PASTE (ATOMIC_, cname) (l);						\
  PASTE (ATOMIC_, cname) (q)

#define ATOMIC(cname, name) \
ATOMIC_LABEL (name):							\
  movb	TCE (OP_ARGS)(%rbx), %r11b;					\
  IF_ATOMIC_SIZE (b, name);						\
  IF_ATOMIC_SIZE (w, name);						\
  IF_ATOMIC_SIZE (l, name);						\
  IF_ATOMIC_SIZE (q, name);						\
  ERROR (ATOMIC_SIZE);							\
									\
  ATOMIC_OP (cname)

  ATOMIC (LOAD, load)
  ATOMIC (STORE, store)
  ATOMIC (INC, inc)
  ATOMIC (DEC, dec)
  ATOMIC (XCHG, xchg)
  ATOMIC (CMPXCHG, cmpxchg)

.lerror:
  ERI_ASSERT_FALSE

  ERI_END_FUNCTION (entry)

/************************************************/
/* do_copy_from_user				*/
/************************************************/

#define COPY_SET_ACCESS(op) \
  ERI_MOV_LM (ERI_PASTE2 (.lcopy_, op, _user),				\
	      TC (ACCESS)(%rdi), %rax);					\
  ERI_MOV_LM (ERI_PASTE2 (.lcopy_, op, _user_fault),			\
	      TC (ACCESS_FAULT)(%rdi), %rax)

#define COPY_RETURN(res) \
  movq	$0, TC (ACCESS)(%rdi);						\
  movb	$res, %al;							\
  ret

ERI_FUNCTION (do_copy_from_user)

  COPY_SET_ACCESS (load)
.lcopy_load:
.lcopy_load_user:
  movb	(%rdx), %al
  movb	%al, (%rsi)
  incq	%rdx
  incq	%rsi
  loop	.lcopy_load

  COPY_RETURN (1)

.lcopy_load_user_fault:
  COPY_RETURN (0)

  ERI_END_FUNCTION (do_copy_from_user)

/************************************************/
/* do_copy_to_user				*/
/************************************************/

ERI_FUNCTION (do_copy_to_user)

  COPY_SET_ACCESS (save)
.lcopy_save:
  movb	(%rdx), %al
.lcopy_save_user:
  movb	%al, (%rsi)
  incq	%rdx
  incq	%rsi
  loop	.lcopy_save

  COPY_RETURN (1)

.lcopy_save_user_fault:
  COPY_RETURN (0)

  ERI_END_FUNCTION (do_copy_to_user)

/************************************************/
/* sig_to					*/
/************************************************/

ERI_FUNCTION (sig_to)
  popq	%rax	/* ctx */

  popq	ERI_UCONTEXT_MCTX_RIP(%rax)
  popq	ERI_UCONTEXT_MCTX_RSP(%rax)

  popq	%rdi	/* th */
  popq	%r11	/* fn */
  call	*%r11
  ERI_END_FUNCTION (sig_to)

/************************************************/
/* sig_act					*/
/************************************************/

ERI_FUNCTION (sig_act)
  movq	%rdi, %rcx
  movq	TC (SIG_ACT_FRAME)(%rcx), %rsp
  leaq	ERI_SIGFRAME_INFO(%rsp), %rsi
  movq	ERI_SIGINFO_SIG(%rsi), %rdi
  leaq	ERI_SIGFRAME_CTX(%rsp), %rdx
  xorq	%rax, %rax
  jmp	*TC (SIG_ACT_ACT)(%rcx)
  ERI_END_FUNCTION (sig_act)

/************************************************/
/* sig_return					*/
/************************************************/

ERI_FUNCTION (sig_return)
  movq	%rdi, %rsp
  ret
  ERI_END_FUNCTION (sig_return)

/************************************************/
/* sig_return_back				*/
/************************************************/

ERI_FUNCTION (sig_return_back)
  movq	%rbx, ERI_SIGFRAME_CTX_MCTX_RBX(%rdi)
  movq	%rsp, ERI_SIGFRAME_CTX_MCTX_RSP(%rdi)
  movq	%rbp, ERI_SIGFRAME_CTX_MCTX_RBP(%rdi)
  movq	%r12, ERI_SIGFRAME_CTX_MCTX_R12(%rdi)
  movq	%r13, ERI_SIGFRAME_CTX_MCTX_R13(%rdi)
  movq	%r14, ERI_SIGFRAME_CTX_MCTX_R14(%rdi)
  movq	%r15, ERI_SIGFRAME_CTX_MCTX_R15(%rdi)
  ERI_MOV_LM (.lsig_return_back, ERI_SIGFRAME_CTX_MCTX_RIP(%rdi), %rax)
  movq	%rdi, %rsp
.lsig_return_back:
  ret
  ERI_END_FUNCTION (sig_return_back)
