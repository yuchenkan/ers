#define ERI_BUILD_ENTRY_OFFSETS_H /* kill circular dependancy */
#include <entry.h>

#include <lib/offset.h>

#define ERI_THREAD_CONTEXT_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_THREAD_CONTEXT_, name,		\
		      struct eri_thread_context, member)

void
declare (void)
{
  ERI_THREAD_ENTRY_OFFSETS (ERI)

  ERI_THREAD_CONTEXT_OFFSET (TOP, top);
  ERI_THREAD_CONTEXT_OFFSET (RSP, rsp);
  ERI_THREAD_CONTEXT_OFFSET (SREGS_RAX, sregs.rax);
  ERI_THREAD_CONTEXT_OFFSET (SREGS_RDI, sregs.rdi);
  ERI_THREAD_CONTEXT_OFFSET (SREGS_RSI, sregs.rsi);
  ERI_THREAD_CONTEXT_OFFSET (SREGS_RDX, sregs.rdx);
  ERI_THREAD_CONTEXT_OFFSET (SREGS_RCX, sregs.rcx);
  ERI_THREAD_CONTEXT_OFFSET (SREGS_R8, sregs.r8);
  ERI_THREAD_CONTEXT_OFFSET (SREGS_R9, sregs.r9);
  ERI_THREAD_CONTEXT_OFFSET (SREGS_R10, sregs.r10);
  ERI_THREAD_CONTEXT_OFFSET (SREGS_R11, sregs.r11);
  ERI_THREAD_CONTEXT_OFFSET (SREGS_RFLAGS, sregs.rflags);
}
