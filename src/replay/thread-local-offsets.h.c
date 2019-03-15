#include <lib/offset.h>
#include <replay/thread-local.h>

#define THREAD_CONTEXT_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (THREAD_CONTEXT_, name, struct thread_context, member)

void
declare (void)
{
  THREAD_CONTEXT_OFFSET (EXT, ext);

  THREAD_CONTEXT_OFFSET (CTX, ctx);

  THREAD_CONTEXT_OFFSET (CTX_ENTRY, ctx.entry);
  THREAD_CONTEXT_OFFSET (CTX_RET, ctx.ret);
  THREAD_CONTEXT_OFFSET (CTX_TOP, ctx.top);

  THREAD_CONTEXT_OFFSET (EREGS, eregs);

  THREAD_CONTEXT_OFFSET (ATOMIC_ACCESS_FAULT, atomic_access_fault);
  THREAD_CONTEXT_OFFSET (TH, th);

  ERI_DECLARE_SYMBOL (THREAD_CONTEXT_SIZE,
		      sizeof (struct thread_context));
}
