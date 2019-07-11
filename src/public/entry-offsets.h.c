#include <lib/util.h>
#include <lib/offset.h>

#include <common/common.h>
#include <common/entry.h>

#define EN_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (_ERS_ENTRY_, name, struct eri_entry, member)

void
declare (void)
{
  EN_OFFSET (OP, _op);
  EN_OFFSET (START, _start);
  EN_OFFSET (LEAVE, _regs.rip);
  EN_OFFSET (ENTER, _th_enter);
  EN_OFFSET (RBX, _regs.rbx);
  EN_OFFSET (ATOMIC_VAL, _atomic.val);
  EN_OFFSET (ATOMIC_MEM, _atomic.mem);
  EN_OFFSET (ATOMIC_LEAVE, _atomic.leave);

#define DECLARE_OP(op) \
  ERI_DECLARE_SYMBOL (ERI_PASTE (_ERS_OP_, op), ERI_PASTE (ERI_OP_, op));
  ERI_FOREACH_PUB_OP (DECLARE_OP)
}
