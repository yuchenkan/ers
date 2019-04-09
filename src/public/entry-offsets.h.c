#include <lib/util.h>
#include <lib/offset.h>

#include <common/thread.h>

#define TE_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (_ERS_THREAD_ENTRY_, name,				\
		      struct eri_thread_entry, member)

void
declare (void)
{
  TE_OFFSET (OP, _op);
  TE_OFFSET (START, _start);
  TE_OFFSET (LEAVE, _leave);
  TE_OFFSET (ENTER, _th_enter);
  TE_OFFSET (RBX, _regs.rbx);
  TE_OFFSET (ATOMIC_VAL, _atomic.val);
  TE_OFFSET (ATOMIC_MEM, _atomic.mem);
  TE_OFFSET (ATOMIC_LEAVE, _atomic.leave);

#define DECLARE_OP(op) \
  ERI_DECLARE_SYMBOL (ERI_PASTE (_ERS_OP_, op), ERI_PASTE (ERI_OP_, op));
  ERI_FOREACH_PUB_OP (DECLARE_OP)
}
