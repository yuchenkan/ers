#include <lib/syscall-common.h>
#include <lib/offset.h>

#define SIGINFO_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_SIGINFO_, name, struct eri_siginfo, member)

#define UCONTEXT_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_UCONTEXT_, name, struct eri_ucontext, member)

#define SIGFRAME_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_SIGFRAME_, name, struct eri_sigframe, member)

void
declare (void)
{
  SIGINFO_OFFSET (SIG, sig);

  UCONTEXT_OFFSET (MCTX_RSP, mctx.rsp);
  UCONTEXT_OFFSET (MCTX_RIP, mctx.rip);
  UCONTEXT_OFFSET (MCTX_RFLAGS, mctx.rflags);

  SIGFRAME_OFFSET (INFO, info);
  SIGFRAME_OFFSET (CTX, ctx);

  SIGFRAME_OFFSET (CTX_MCTX_R8, ctx.mctx.r8);
  SIGFRAME_OFFSET (CTX_MCTX_R9, ctx.mctx.r9);
  SIGFRAME_OFFSET (CTX_MCTX_R10, ctx.mctx.r10);
  SIGFRAME_OFFSET (CTX_MCTX_R11, ctx.mctx.r11);
  SIGFRAME_OFFSET (CTX_MCTX_R12, ctx.mctx.r12);
  SIGFRAME_OFFSET (CTX_MCTX_R13, ctx.mctx.r13);
  SIGFRAME_OFFSET (CTX_MCTX_R14, ctx.mctx.r14);
  SIGFRAME_OFFSET (CTX_MCTX_R15, ctx.mctx.r15);
  SIGFRAME_OFFSET (CTX_MCTX_RDI, ctx.mctx.rdi);
  SIGFRAME_OFFSET (CTX_MCTX_RSI, ctx.mctx.rsi);
  SIGFRAME_OFFSET (CTX_MCTX_RBP, ctx.mctx.rbp);
  SIGFRAME_OFFSET (CTX_MCTX_RBX, ctx.mctx.rbx);
  SIGFRAME_OFFSET (CTX_MCTX_RDX, ctx.mctx.rdx);
  SIGFRAME_OFFSET (CTX_MCTX_RAX, ctx.mctx.rax);
  SIGFRAME_OFFSET (CTX_MCTX_RCX, ctx.mctx.rcx);
  SIGFRAME_OFFSET (CTX_MCTX_RSP, ctx.mctx.rsp);
  SIGFRAME_OFFSET (CTX_MCTX_RIP, ctx.mctx.rip);
  SIGFRAME_OFFSET (CTX_MCTX_RFLAGS, ctx.mctx.rflags);

  SIGFRAME_OFFSET (CTX_MCTX_RIP, ctx.mctx.rip);
}
