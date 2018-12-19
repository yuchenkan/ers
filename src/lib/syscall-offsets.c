#include "lib/offset.h"
#include "lib/syscall.h"

#define SIGMASK_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_SIGMASK_, name, struct eri_sigmask, member)

#define STACK_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_STACK_, name, struct eri_stack, member)

#define SIGINFO_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_SIGINFO_, name, struct eri_siginfo, member)

#define UCONTEXT_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_UCONTEXT_, name, struct eri_ucontext, member)

void
declare (void)
{
  SIGMASK_OFFSET (MASK_ALL, mask_all);
  SIGMASK_OFFSET (MASK, mask);

  ERI_DECLARE_SYMBOL (ERI_SIGMASK_SIZE16,
		      eri_size_of (struct eri_sigmask, 16));

  STACK_OFFSET (SP, sp);
  STACK_OFFSET (FLAGS, flags);
  STACK_OFFSET (SIZE, size);

  ERI_DECLARE_SYMBOL (ERI_STACK_SIZE16, eri_size_of (struct eri_stack, 16));

  SIGINFO_OFFSET (CODE, code);

  UCONTEXT_OFFSET (STACK_SP, stack.sp);

  UCONTEXT_OFFSET (MCTX_R8, mctx.r8);
  UCONTEXT_OFFSET (MCTX_R9, mctx.r9);
  UCONTEXT_OFFSET (MCTX_R10, mctx.r10);
  UCONTEXT_OFFSET (MCTX_R11, mctx.r11);
  UCONTEXT_OFFSET (MCTX_R12, mctx.r12);
  UCONTEXT_OFFSET (MCTX_R13, mctx.r13);
  UCONTEXT_OFFSET (MCTX_R14, mctx.r14);
  UCONTEXT_OFFSET (MCTX_R15, mctx.r15);
  UCONTEXT_OFFSET (MCTX_RDI, mctx.rdi);
  UCONTEXT_OFFSET (MCTX_RSI, mctx.rsi);
  UCONTEXT_OFFSET (MCTX_RBP, mctx.rbp);
  UCONTEXT_OFFSET (MCTX_RBX, mctx.rbx);
  UCONTEXT_OFFSET (MCTX_RDX, mctx.rdx);
  UCONTEXT_OFFSET (MCTX_RAX, mctx.rax);
  UCONTEXT_OFFSET (MCTX_RCX, mctx.rcx);
  UCONTEXT_OFFSET (MCTX_RSP, mctx.rsp);
  UCONTEXT_OFFSET (MCTX_RIP, mctx.rip);
  UCONTEXT_OFFSET (MCTX_RFLAGS, mctx.rflags);
}
