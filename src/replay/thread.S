/* vim: set ft=gas: */

#include <entry.h>
#include <lib/util.h>

#include <replay/thread-local-offsets.h>

#define TC(name)	PASTE (THREAD_CONTEXT_, name)
#define TCE(name)	TC (PASTE (EXT_, name))
#define TCC(name)	TC (PASTE (CTX_, name))

  .section .rodata

ERI_ENTRY_THREAD_ENTRY_TEXT (thread_context, TC (SIZE), TCC (ENTRY), TC (EXT))

  .text

#define TH_CALL(fn) \
  movq	TC (TH)(%rbx), %rdi;						\
  call	fn

ERI_FUNCTION (main)
  movq	%rdi, %rbx
  movq	TCC (TOP)(%rbx), %rsp
  TH_CALL (start_main)

  /* XXX: ensure eregs all zero */
  ERI_ENTRY_THREAD_CONTEXT_RESTORE (TC (CTX))
  jmp	*TCC (RET)(%rbx)
  ERI_END_FUNCTION (start_main)

ERI_ENTRY_THREAD_CONTEXT_ENTRY (entry, TC (CTX))

  ERI_ENTRY_SAVE_EREGS (TC (EREGS))

  TH_CALL (relax)

  ERI_ENTRY_SYSCALL_MAY_RESTORE_EREGS (TC (EREGS), entry)

  ERI_ENTRY_THREAD_CONTEXT_RESTORE (TC (CTX))
  jmp	*TCC (RET)(%rbx)

  ERI_END_FUNCTION (entry)
