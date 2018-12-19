#include "lib/offset.h"
#include "tst/tst-live-entry-common.h"

#define TST_CONTEXT_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (TST_CONTEXT_, name, struct tst_context, member)

void
declare (void)
{
  TST_CONTEXT_OFFSET (RAX, rax);
  TST_CONTEXT_OFFSET (RBX, rbx);
  TST_CONTEXT_OFFSET (RCX, rcx);
  TST_CONTEXT_OFFSET (RDX, rdx);
  TST_CONTEXT_OFFSET (RDI, rdi);
  TST_CONTEXT_OFFSET (RSI, rsi);
  TST_CONTEXT_OFFSET (RBP, rbp);
  TST_CONTEXT_OFFSET (RSP, rsp);
  TST_CONTEXT_OFFSET (R8, r8);
  TST_CONTEXT_OFFSET (R9, r9);
  TST_CONTEXT_OFFSET (R10, r10);
  TST_CONTEXT_OFFSET (R11, r11);
  TST_CONTEXT_OFFSET (R12, r12);
  TST_CONTEXT_OFFSET (R13, r13);
  TST_CONTEXT_OFFSET (R14, r14);
  TST_CONTEXT_OFFSET (R15, r15);
  TST_CONTEXT_OFFSET (RIP, rip);
  TST_CONTEXT_OFFSET (RFLAGS, rflags);
}
