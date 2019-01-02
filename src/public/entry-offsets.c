#include "lib/offset.h"
#include "entry.h"

#define THREAD_ENTRY_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (_ERS_THREAD_ENTRY_, name,				\
		      struct eri_public_thread_entry, member)

void
declare (void)
{
  THREAD_ENTRY_OFFSET (MARK, mark);
  THREAD_ENTRY_OFFSET (OP, op);

  THREAD_ENTRY_OFFSET (START, start);
  THREAD_ENTRY_OFFSET (RET, ret);
  THREAD_ENTRY_OFFSET (CONT, cont);

  THREAD_ENTRY_OFFSET (DIR, dir);

  THREAD_ENTRY_OFFSET (RBX, rbx);
  THREAD_ENTRY_OFFSET (VAR0, var[0]);
  THREAD_ENTRY_OFFSET (VAR1, var[1]);

  THREAD_ENTRY_OFFSET (THREAD_ENTRY, thread_entry);
}
