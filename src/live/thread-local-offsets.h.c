#include <lib/util.h>
#include <lib/offset.h>
#include <live/thread-local.h>

#define THREAD_CONTEXT_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (THREAD_CONTEXT_, name, struct thread_context, member)

void
declare (void)
{
  THREAD_CONTEXT_OFFSET (EXT, ext);

  THREAD_CONTEXT_OFFSET (EXT_OP_SIG_HAND, ext.op.sig_hand);
  THREAD_CONTEXT_OFFSET (EXT_OP_ARGS, ext.op.args);
  THREAD_CONTEXT_OFFSET (EXT_OP_CODE, ext.op.code);
  THREAD_CONTEXT_OFFSET (EXT_RBX, ext.rbx);
  THREAD_CONTEXT_OFFSET (EXT_RET, ext.ret);
  THREAD_CONTEXT_OFFSET (EXT_CALL, ext.call);
  THREAD_CONTEXT_OFFSET (EXT_ENTRY, ext.entry);
  THREAD_CONTEXT_OFFSET (EXT_ATOMIC_VAL, ext.atomic.val);
  THREAD_CONTEXT_OFFSET (EXT_ATOMIC_RET, ext.atomic.ret);

  THREAD_CONTEXT_OFFSET (CTX, ctx);

  THREAD_CONTEXT_OFFSET (CTX_ENTRY, ctx.entry);
  THREAD_CONTEXT_OFFSET (CTX_RET, ctx.ret);
  THREAD_CONTEXT_OFFSET (CTX_TOP, ctx.top);
  THREAD_CONTEXT_OFFSET (CTX_RSP, ctx.rsp);

#define THREAD_CONTEXT_SREG_OFFSET(creg, reg) \
  THREAD_CONTEXT_OFFSET (ERI_PASTE (CTX_SREGS_, creg), ctx.sregs.reg);
  ERI_ENTRY_FOREACH_SREG (THREAD_CONTEXT_SREG_OFFSET)

  THREAD_CONTEXT_OFFSET (SIG_FRAME, sig_frame);

  THREAD_CONTEXT_OFFSET (ACCESS, access);
  THREAD_CONTEXT_OFFSET (ACCESS_FAULT, access_fault);

  THREAD_CONTEXT_OFFSET (SYSCALL_EREGS, syscall.eregs);

  THREAD_CONTEXT_OFFSET (TH, th);

  ERI_DECLARE_SYMBOL (THREAD_CONTEXT_SIZE,
		      sizeof (struct thread_context));

#define SIG_HAND_SYMBOL(chand, hand) \
  ERI_DECLARE_SYMBOL (chand, chand);

  SIG_HANDS (SIG_HAND_SYMBOL)
}
