#include "vex.h"
#include "lib/offset.h"

#define RW_RANGES_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (VEX_RW_RANGES_, name, struct vex_rw_ranges, member)

#define CTX_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (VEX_CTX_, name, struct vex_context, member)

void
declare (void)
{
  RW_RANGES_OFFSET (NADDRS, naddrs);
  RW_RANGES_OFFSET (NSIZES, nsizes);
  RW_RANGES_OFFSET (ADDRS, addrs);
  RW_RANGES_OFFSET (SIZES, sizes);

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

  CTX_OFFSET (READS, reads);
  CTX_OFFSET (WRITES, writes);
}
