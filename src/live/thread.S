/* vim: set ft=gas: */

#include <lib/util.h>
#include <lib/syscall.h>
#include <lib/syscall-offsets.h>
#include <lib/registers.h>

#include <entry.h>
#include <public/common.h>
#include <live/thread-local-offsets.h>

#define RAX(sz)		ERI_RAX (sz)
#define RBX(sz)		ERI_RBX (sz)
#define RCX(sz)		ERI_RCX (sz)
#define RDX(sz)		ERI_RDX (sz)
#define RDI(sz)		ERI_RDI (sz)
#define RSI(sz)		ERI_RSI (sz)
#define RSP(sz)		ERI_RSP (sz)
#define RBP(sz)		ERI_RBP (sz)
#define R8(sz)		ERI_R8 (sz)
#define R9(sz)		ERI_R9 (sz)
#define R10(sz)		ERI_R10 (sz)
#define R11(sz)		ERI_R11 (sz)
#define R12(sz)		ERI_R12 (sz)
#define R13(sz)		ERI_R13 (sz)
#define R14(sz)		ERI_R14 (sz)
#define R15(sz)		ERI_R15 (sz)

#define PASTE		ERI_PASTE

#define TC(name)	PASTE (THREAD_CONTEXT_, name)
#define TCE(name)	TC (PASTE (EXT_, name))
#define TCC(name)	TC (PASTE (CTX_, name))

  .section .rodata

/************************************************/
/* thread_context_text				*/
/************************************************/

ERI_THREAD_ENTRY_TEXT (thread_context, TC (SIZE), TCC (ENTRY), TC (EXT))

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
  movq	TCC (SREGS_RCX)(%rbx), %rcx;					\
  jmp	*TCC (RET)(%rbx)

#define SIG_SAVE_CTX_REG(creg, reg, frame) \
  movq	%reg, ERI_PASTE (ERI_SIGFRAME_CTX_MCTX_, creg)(frame)

#define SIG_RETURN_ACTION(action, ret) \
  movq	TC (SIG_FRAME)(%rbx), %rcx;					\
  SIG_SAVE_CTX_REG (RSP, rsp, %rcx);					\
  movq	TCC (TOP)(%rbx), %rsp;						\
  pushfq;								\
  popq	ERI_SIGFRAME_CTX_MCTX_RFLAGS(%rcx);				\
  pushq	$0;								\
  popfq;								\
  FOREACH_SGREG_NO_RCX (SIG_SAVE_CTX_REG, %rcx);			\
  ERI_MOV_MM (TCE (RBX)(%rbx),						\
	      ERI_SIGFRAME_CTX_MCTX_RBX(%rcx), %rax);			\
  ERI_MOV_MM (TCE (ERI_PP_IIF (ret, RET, CALL))(%rbx),			\
	      ERI_SIGFRAME_CTX_MCTX_RIP(%rcx), %rax);			\
  ERI_MOV_MM (TCC (SREGS_RCX)(%rbx),					\
	      ERI_SIGFRAME_CTX_MCTX_RCX(%rcx), %rax);			\
  FOREACH_EREG (SIG_SAVE_CTX_REG, %rcx);				\
  TH_CALL (action)

#define SIG_RETURN_TO_USER(label) \
  SIG_RETURN (RETURN_TO_USER, label);					\
label:									\
  SIG_RETURN_ACTION (sig_action, 1)

/************************************************/
/* main						*/
/************************************************/

ERI_FUNCTION (main)
  movq	%rdi, %rbx
  TH_CALL (start_main)

  movq	$0, TCE (RBX)(%rbx)
  movq	$0, TCC (SREGS_RCX)(%rbx)

#define ZERO_REG(creg, reg) \
  xorq	%reg, %reg

  FOREACH_SGREG_NO_RCX_RDX (ZERO_REG)
  FOREACH_EREG (ZERO_REG)

  movq	TCC (SREGS_RDX)(%rbx), %rdx
  pushq	$0
  popfq
  movq	TCC (RSP)(%rbx), %rsp

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

ERI_THREAD_CONTEXT_ENTRY (entry, TC (CTX))

#define RESTORE_SGREG(creg, reg) \
  movq	TCC (PASTE (SREGS_, creg))(%rbx), %reg				\

#define RESTORE_NO_RCX \
  FOREACH_SGREG_NO_RCX (RESTORE_SGREG);					\
  pushq	TCC (SREGS_RFLAGS)(%rbx);					\
  popfq;								\
  movq	TCC (RSP)(%rbx), %rsp

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

  testq	%rax, %rax
  jz	.lsyscall_no_extra_restore
  cmpq	$1, %rax
  je	.lsyscall_extra_restore
  movq	%rax, %rbx /* clone child start */

.lsyscall_extra_restore:
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

  SIG_RETURN_ACTION (sig_restart_sync_async, 0)

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
  leaq	ATOMIC_ACCESS_START_LABEL (sz, name)(%rip), %rsi;		\
  leaq	ATOMIC_ACCESS_END_LABEL (sz, name)(%rip), %rdx;			\
  TH_CALL (prepare_atomic)

#define COMPLETE_ATOMIC(sz, name) \
  TH_CALL (complete_atomic);						\
									\
  RESTORE_NO_RCX;							\
  SIG_RETURN_TO_USER (ATOMIC_SIZE_LABEL (sz, PASTE (name, _sig_return)))

#define ATOMIC_LOAD_RFLAGS \
  pushq	TCC (SREGS_RFLAGS)(%rbx);					\
  popfq

#define ATOMIC_SAVE_RFLAGS \
  pushfq;								\
  popq	TCC (SREGS_RFLAGS)(%rbx)

/************************************************/
/* entry: atomic_ext_return			*/
/************************************************/

.latomic_ext_return:
  movq	%rcx, TCC (SREGS_RCX)(%rbx)
  ERI_MOV_LM (entry, TCC (ENTRY)(%rbx), %rcx)
  ERI_MOV_MM (TCE (ATOMIC_RET)(%rbx), TCE (RET)(%rbx), %rcx)

  SIG_RETURN_TO_USER (.latomic_ext_return_sig_return)

#define EXT_COMPLETE_ATOMIC \
  TH_CALL (complete_atomic);						\
									\
  ERI_MOV_LM (.latomic_ext_return, TCC (ENTRY)(%rbx), %rax);		\
  RESTORE;								\
  jmp	*TCC (RET)(%rbx)

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
  movq	TCC (SREGS_RAX)(%rbx), %rax;					\
  ATOMIC_LOAD_RFLAGS;							\
ATOMIC_ACCESS_START_LABEL (sz, cmpxchg):				\
  PASTE (mov, sz)	(%rdi), %RSI (sz);				\
  PASTE (cmpxchg, sz)	%R11 (sz), (%rdi);				\
ATOMIC_ACCESS_END_LABEL (sz, cmpxchg):					\
									\
  ATOMIC_SAVE_RFLAGS;							\
  movq	%rax, TCC (SREGS_RAX)(%rbx);					\
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
  .cfi_startproc

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

  .cfi_endproc
  ERI_END_FUNCTION (do_copy_from_user)

/************************************************/
/* do_copy_to_user				*/
/************************************************/

ERI_FUNCTION (do_copy_to_user)
  .cfi_startproc

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

  .cfi_endproc
  ERI_END_FUNCTION (do_copy_to_user)

/************************************************/
/* sig_to					*/
/************************************************/

ERI_FUNCTION (sig_to)
  popq	%rax	/* ctx */

  popq	ERI_UCONTEXT_MCTX_RIP(%rax)
  popq	ERI_UCONTEXT_MCTX_RSP(%rax)
  popq	ERI_UCONTEXT_MCTX_RFLAGS(%rax)

  popq	%rdi	/* th */
  popq	%r11	/* fn */
  jmp	*%r11
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
