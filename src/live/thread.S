/* vim: set ft=gas: */

#include <public/impl/common.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <lib/syscall.h>
#include <lib/syscall-offsets.h>

#include <common/entry.h>
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

#define PASTE(x, y)	ERI_PASTE (x, y)
#define PASTE2(x, y, z)	ERI_PASTE2 (x, y, z)

#define TC(name)	PASTE (THREAD_CONTEXT_, name)
#define TCE(name)	TC (PASTE (EXT_, name))
#define TCC(name)	TC (PASTE (CTX_, name))

  .section .rodata

ERI_ENTRY_THREAD_ENTRY_TEXT (thread_context, TC (SIZE), TCC (ENTRY), TC (EXT))

  .text

#define LABEL(name)			PASTE (.L, name)

#define TH_CALL(fn) \
  movq	TC (TH)(%rbx), %rdi;						\
  call	fn

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
  movq	%reg, PASTE (ERI_SIGFRAME_CTX_MCTX_, creg)(frame);

#define SIG_RETURN_ACTION(action, ret) \
  movq	TC (SIG_FRAME)(%rbx), %rcx;					\
  SIG_SAVE_CTX_REG (RSP, rsp, %rcx)					\
  movq	TCC (TOP)(%rbx), %rsp;						\
  pushfq;								\
  popq	ERI_SIGFRAME_CTX_MCTX_RFLAGS(%rcx);				\
  pushq	$0;								\
  popfq;								\
  ERI_ENTRY_FOREACH_SGREG_NO_RCX (SIG_SAVE_CTX_REG, %rcx)		\
  ERI_MOV_MM (TCE (RBX)(%rbx),						\
	      ERI_SIGFRAME_CTX_MCTX_RBX(%rcx), %rax);			\
  ERI_MOV_MM (TCE (ERI_PP_IIF (ret, RET, CALL))(%rbx),			\
	      ERI_SIGFRAME_CTX_MCTX_RIP(%rcx), %rax);			\
  ERI_MOV_MM (TCC (SREGS_RCX)(%rbx),					\
	      ERI_SIGFRAME_CTX_MCTX_RCX(%rcx), %rax);			\
  ERI_ENTRY_FOREACH_EREG (SIG_SAVE_CTX_REG, %rcx)			\
  TH_CALL (action)

#define SIG_RETURN_TO_USER(label) \
  SIG_RETURN (RETURN_TO_USER, label);					\
label:									\
  SIG_RETURN_ACTION (sig_action, 1)

ERI_FUNCTION (main)
  movq	%rdi, %rbx
  TH_CALL (start_main)

  ERI_ENTRY_RESTORE_EREGS (TC (SYSCALL_EREGS))
  ERI_ENTRY_THREAD_CONTEXT_RESTORE_NO_RCX (TC (CTX))

  SIG_RETURN_TO_USER (.lmain_sig_return)

  ERI_END_FUNCTION (main)

#define ERROR_OP_CODE		0
#define ERROR_ATOMIC_SIZE	1

#define ERROR(code) \
  movq	PASTE (ERROR_, code), %r14;					\
  jmp	.lerror

ERI_ENTRY_THREAD_CONTEXT_ENTRY (entry, TC (CTX))

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

.lsyscall:
  ERI_ENTRY_SYSCALL_MAY_SAVE_EREGS (TC (SYSCALL_EREGS), syscall)
  TH_CALL (syscall)
  ERI_ENTRY_SYSCALL_MAY_RESTORE_EREGS (TC (SYSCALL_EREGS), syscall)

  ERI_ENTRY_THREAD_CONTEXT_RESTORE_NO_RCX (TC (CTX))
  SIG_RETURN_TO_USER (.lsyscall_sig_return)

.lsync_async:

  movq	%rcx, %rsi
  TH_CALL (sync_async)

  ERI_ENTRY_THREAD_CONTEXT_RESTORE_NO_RCX (TC (CTX))
  SIG_RETURN (SYNC_ASYNC_RETURN_TO_USER, .lsync_async_sig_return)

.lsync_async_sig_return:

  SIG_RETURN_ACTION (sig_restart_sync_async, 0)

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
  ERI_ENTRY_THREAD_CONTEXT_RESTORE_NO_RCX (TC (CTX));			\
  SIG_RETURN_TO_USER (ATOMIC_SIZE_LABEL (sz, PASTE (name, _sig_return)))

#define ATOMIC_LOAD_RFLAGS \
  pushq	TCC (SREGS_RFLAGS)(%rbx);					\
  popfq

#define ATOMIC_SAVE_RFLAGS \
  pushfq;								\
  popq	TCC (SREGS_RFLAGS)(%rbx)

.latomic_ext_return:
  movq	%rcx, TCC (SREGS_RCX)(%rbx)
  ERI_MOV_LM (entry, TCC (ENTRY)(%rbx), %rcx)
  ERI_MOV_MM (TCE (ATOMIC_RET)(%rbx), TCE (RET)(%rbx), %rcx)

  SIG_RETURN_TO_USER (.latomic_ext_return_sig_return)

#define EXT_COMPLETE_ATOMIC \
  TH_CALL (complete_atomic);						\
									\
  ERI_MOV_LM (.latomic_ext_return, TCC (ENTRY)(%rbx), %rax);		\
  ERI_ENTRY_THREAD_CONTEXT_RESTORE (TC (CTX));				\
  jmp	*TCC (RET)(%rbx)

/* atomic_load */

#define ATOMIC_LOAD(sz) \
PREPARE_ATOMIC (sz, load);						\
									\
ATOMIC_ACCESS_START_LABEL (sz, load):					\
  PASTE (mov, sz)	(%rax), %RSI (sz);				\
ATOMIC_ACCESS_END_LABEL (sz, load):					\
									\
  EXT_COMPLETE_ATOMIC

/* atomic_store	*/

#define ATOMIC_STORE(sz) \
PREPARE_ATOMIC (sz, store);						\
									\
  movq	TCE (ATOMIC_VAL)(%rbx), %rdx;					\
ATOMIC_ACCESS_START_LABEL (sz, store):					\
  PASTE (mov, sz)	(%rax), %RSI (sz);				\
  PASTE (mov, sz)	%RDX (sz), (%rax);				\
ATOMIC_ACCESS_END_LABEL (sz, store):					\
									\
  COMPLETE_ATOMIC (sz, store)

/* atomic_inc / atomic_dec */

#define ATOMIC_INC_DEC(sz, inc) \
PREPARE_ATOMIC (sz, inc);						\
									\
  ATOMIC_LOAD_RFLAGS;							\
ATOMIC_ACCESS_START_LABEL (sz, inc):					\
  PASTE (inc, sz)	(%rax);						\
ATOMIC_ACCESS_END_LABEL (sz, inc):					\
									\
  ATOMIC_SAVE_RFLAGS;							\
  COMPLETE_ATOMIC (sz, inc)

#define ATOMIC_INC(sz)	ATOMIC_INC_DEC (sz, inc)
#define ATOMIC_DEC(sz)	ATOMIC_INC_DEC (sz, dec)

/* eri_live_entry: atomic_xchg */

#define ATOMIC_XCHG(sz) \
PREPARE_ATOMIC (sz, xchg);						\
									\
  movq	TCE (ATOMIC_VAL)(%rbx), %rdx;					\
ATOMIC_ACCESS_START_LABEL (sz, xchg):					\
  PASTE (mov, sz)	(%rax), %RSI (sz);				\
  PASTE (mov, sz)	%RDX (sz), (%rax);				\
ATOMIC_ACCESS_END_LABEL (sz, xchg):					\
									\
  EXT_COMPLETE_ATOMIC

/* atomic_cmpxchg */

#define ATOMIC_CMPXCHG(sz) \
PREPARE_ATOMIC (sz, cmpxchg);						\
									\
  movq	TCE (ATOMIC_VAL)(%rbx), %rdx;					\
  movq	%rax, %r11;							\
  movq	TCC (SREGS_RAX)(%rbx), %rax;					\
  ATOMIC_LOAD_RFLAGS;							\
ATOMIC_ACCESS_START_LABEL (sz, cmpxchg):				\
  PASTE (mov, sz)	(%r11), %RSI (sz);				\
  PASTE (cmpxchg, sz)	%RDX (sz), (%r11);				\
ATOMIC_ACCESS_END_LABEL (sz, cmpxchg):					\
									\
  ATOMIC_SAVE_RFLAGS;							\
  movq	%rax, TCC (SREGS_RAX)(%rbx);					\
  COMPLETE_ATOMIC (sz, cmpxchg)

/* atomic */

#define IF_ATOMIC_SIZE(sz, name) \
  cmpb	$_ERS_ATOMIC_SIZE (sz), %r11b;					\
  je	ATOMIC_SIZE_LABEL (sz, name);

#define ATOMIC_OP_SIZE(sz, op)		op (sz);

#define ATOMIC_OP(cname) \
  ERI_FOREACH_REG_SIZE (ATOMIC_OP_SIZE,	PASTE (ATOMIC_, cname))

#define ATOMIC(cname, name) \
ATOMIC_LABEL (name):							\
  movb	TCE (OP_ARGS)(%rbx), %r11b;					\
  ERI_FOREACH_REG_SIZE (IF_ATOMIC_SIZE, name)				\
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

ERI_ENTRY_DEFINE_DO_COPY_USER ()

ERI_FUNCTION (sig_to)
  popq	%rax	/* ctx */

  popq	ERI_UCONTEXT_MCTX_RIP(%rax)
  popq	ERI_UCONTEXT_MCTX_RSP(%rax)
  popq	ERI_UCONTEXT_MCTX_RFLAGS(%rax)

  popq	%rdi	/* th */
  popq	%r11	/* fn */
  jmp	*%r11
  ERI_END_FUNCTION (sig_to)

ERI_FUNCTION (sig_return)
  movq	%rdi, %rsp
  ret
  ERI_END_FUNCTION (sig_return)

ERI_FUNCTION (syscall_intr_sys_syscall)

  pushq	%rbx
  pushq	%rbp

  movq	%rdi, %rbx
  movq	%rsi, %rbp

  ERI_MOV_LM (.lsyscall_intr, TC (SYSCALL_SIG_INTR)(%rbx), %rax)

  cmpq	$1, TC (SIG_FRAME)(%rbx)
  je	.lsyscall_intr_syscall
  movq	$ERI_EINTR, %rax
  jmp	.lsyscall_intr

.lsyscall_intr_syscall:
  movq	ERI_SYS_SYSCALL_ARGS_NR(%rbp), %rax

  movq	ERI_SYS_SYSCALL_ARGS_A0(%rbp), %rdi
  movq	ERI_SYS_SYSCALL_ARGS_A1(%rbp), %rsi
  movq	ERI_SYS_SYSCALL_ARGS_A2(%rbp), %rdx
  movq	ERI_SYS_SYSCALL_ARGS_A3(%rbp), %r10
  movq	ERI_SYS_SYSCALL_ARGS_A4(%rbp), %r8
  movq	ERI_SYS_SYSCALL_ARGS_A5(%rbp), %r9
  syscall
.lsyscall_intr:
  movq	$0, TC (SYSCALL_SIG_INTR)(%rbx)
  movq	%rax, ERI_SYS_SYSCALL_ARGS_RESULT(%rbp)
  popq	%rbp
  popq	%rbx
  ret

  ERI_END_FUNCTION (syscall_intr_sys_syscall)
