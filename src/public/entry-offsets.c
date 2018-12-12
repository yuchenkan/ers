#include "lib/offset.h"
#include "entry.h"

#define COMMON_THREAD_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (_ERS_COMMON_THREAD_, name, struct eri_common_thread, member)

void
declare (void)
{
  COMMON_THREAD_OFFSET (MARK, mark);
  COMMON_THREAD_OFFSET (OP, op);

  COMMON_THREAD_OFFSET (START, start);
  COMMON_THREAD_OFFSET (RET, ret);
  COMMON_THREAD_OFFSET (CONT, cont);

  COMMON_THREAD_OFFSET (DIR, dir);

  COMMON_THREAD_OFFSET (RBX, rbx);
  COMMON_THREAD_OFFSET (VAR0, var[0]);
  COMMON_THREAD_OFFSET (VAR1, var[1]);

  COMMON_THREAD_OFFSET (THREAD_ENTRY, thread_entry);
}
