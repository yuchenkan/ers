#include <live-thread-local.h>

#include <lib/offset.h>

#define THREAD_CONTEXT_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (THREAD_CONTEXT_, name, struct thread_context, member)

void
declare (void)
{
  THREAD_CONTEXT_OFFSET (EXT_OP_SIG_HAND, ext.op.sig_hand);
  THREAD_CONTEXT_OFFSET (EXT_OP_ARGS, ext.op.args);
  THREAD_CONTEXT_OFFSET (EXT_OP_CODE, ext.op.code);
  THREAD_CONTEXT_OFFSET (EXT_RBX, ext.rbx);
  THREAD_CONTEXT_OFFSET (EXT_RET, ext.ret);
  THREAD_CONTEXT_OFFSET (EXT_CALL, ext.call);
  THREAD_CONTEXT_OFFSET (EXT_ENTRY, ext.entry);
  THREAD_CONTEXT_OFFSET (EXT_ATOMIC_VAL, ext.atomic.val);
  THREAD_CONTEXT_OFFSET (EXT_ATOMIC_RET, ext.atomic.ret);

  THREAD_CONTEXT_OFFSET (ENTRY, entry);

  THREAD_CONTEXT_OFFSET (RET, ret);
  THREAD_CONTEXT_OFFSET (TOP, top);
  THREAD_CONTEXT_OFFSET (RSP, rsp);

  THREAD_CONTEXT_OFFSET (SREGS_RAX, sregs.rax);
  THREAD_CONTEXT_OFFSET (SREGS_RDI, sregs.rdi);
  THREAD_CONTEXT_OFFSET (SREGS_RSI, sregs.rsi);
  THREAD_CONTEXT_OFFSET (SREGS_RDX, sregs.rdx);
  THREAD_CONTEXT_OFFSET (SREGS_RCX, sregs.rcx);
  THREAD_CONTEXT_OFFSET (SREGS_R8, sregs.r8);
  THREAD_CONTEXT_OFFSET (SREGS_R9, sregs.r9);
  THREAD_CONTEXT_OFFSET (SREGS_R10, sregs.r10);
  THREAD_CONTEXT_OFFSET (SREGS_R11, sregs.r11);
  THREAD_CONTEXT_OFFSET (SREGS_RFLAGS, sregs.rflags);

  THREAD_CONTEXT_OFFSET (SIG_FRAME, sig_frame);
  THREAD_CONTEXT_OFFSET (SIG_ACT_ACT, sig_act.act);
  THREAD_CONTEXT_OFFSET (SIG_ACT_FRAME, sig_act_frame);

  THREAD_CONTEXT_OFFSET (ACCESS, access);
  THREAD_CONTEXT_OFFSET (ACCESS_FAULT, access_fault);

  THREAD_CONTEXT_OFFSET (SYSCALL_EREGS_RBP, syscall.eregs.rbp);
  THREAD_CONTEXT_OFFSET (SYSCALL_EREGS_R12, syscall.eregs.r12);
  THREAD_CONTEXT_OFFSET (SYSCALL_EREGS_R13, syscall.eregs.r13);
  THREAD_CONTEXT_OFFSET (SYSCALL_EREGS_R14, syscall.eregs.r14);
  THREAD_CONTEXT_OFFSET (SYSCALL_EREGS_R15, syscall.eregs.r15);

  THREAD_CONTEXT_OFFSET (TH, th);

  ERI_DECLARE_SYMBOL (THREAD_CONTEXT_SIZE16,
		      eri_size_of (struct thread_context, 16));

#define SIG_HAND_SYMBOL(chand, hand) \
  ERI_DECLARE_SYMBOL (chand, chand);

  SIG_HANDS (SIG_HAND_SYMBOL)
}
