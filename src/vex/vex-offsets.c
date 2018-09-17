#include "vex.h"

#define DECLARE_I(sym, val) \
  asm ("__AS_DEFINE__ " #sym "\t%c0" :: "n" ((unsigned long) (val)))
#define DECLARE(sym, val) DECLARE_I (sym, val)

#define STR_CAT_I(x, y) x##y
#define STR_CAT(x, y) STR_CAT_I (x, y)

#define CTX_OFFSET(name, member) \
  DECLARE (STR_CAT (VEX_CTX_, name), __builtin_offsetof (struct vex_context, member))

void
declare (void)
{
  CTX_OFFSET (CTX, ctx);

  CTX_OFFSET (SYSCALL, syscall);
  CTX_OFFSET (BACK, back);

  CTX_OFFSET (RIP, comm.rip);

  CTX_OFFSET (RAX, comm.rax);
  CTX_OFFSET (RCX, comm.rcx);
  CTX_OFFSET (RDX, comm.rdx);
  CTX_OFFSET (RBX, comm.rbx);
  CTX_OFFSET (RSP, comm.rsp);
  CTX_OFFSET (RBP, comm.rbp);
  CTX_OFFSET (RSI, comm.rsi);
  CTX_OFFSET (RDI, comm.rdi);
  CTX_OFFSET (R8, comm.r8);
  CTX_OFFSET (R9, comm.r9);
  CTX_OFFSET (R10, comm.r10);
  CTX_OFFSET (R11, comm.r11);
  CTX_OFFSET (R12, comm.r12);
  CTX_OFFSET (R13, comm.r13);
  CTX_OFFSET (R14, comm.r14);
  CTX_OFFSET (R15, comm.r15);

  CTX_OFFSET (RFLAGS, comm.rflags);
  CTX_OFFSET (FSBASE, comm.fsbase);

  CTX_OFFSET (XSAVE, comm.xsave);

  CTX_OFFSET (INSTS, insts);

  CTX_OFFSET (RET, ret);
  CTX_OFFSET (TOP, top);
}
