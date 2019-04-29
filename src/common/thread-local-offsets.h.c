#include <lib/util.h>
#include <lib/offset.h>
#include <common/thread.h>

#define EN_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (EN_, name, struct eri_entry, member)

#define EN_REG_OFFSET(creg, reg) \
  EN_OFFSET (ERI_PASTE (_REGS_, creg), _regs.reg);

void
declare (void)
{
  EN_OFFSET (_ENTER, _enter);
  EN_OFFSET (_TH_LEAVE, _th_leave);
  ERI_FOREACH_REG (EN_REG_OFFSET)
  EN_OFFSET (_SIG_PENDING, _sig_pending);
  EN_OFFSET (_STACK, _stack);
  EN_OFFSET (_ENTRY, _entry);
  EN_OFFSET (_SIG_ACTION, _sig_action);

  EN_OFFSET (_ACCESS_RBX, _access.rbx);
  EN_OFFSET (_ACCESS_RSP, _access.rsp);
  EN_OFFSET (_ACCESS_RBP, _access.rbp);
  EN_OFFSET (_ACCESS_R12, _access.r12);
  EN_OFFSET (_ACCESS_R13, _access.r13);
  EN_OFFSET (_ACCESS_R14, _access.r14);
  EN_OFFSET (_ACCESS_R15, _access.r15);
  EN_OFFSET (_ACCESS_RIP, _access.rip);
  EN_OFFSET (_TEST_ACCESS, _test_access);

  EN_OFFSET (_SYSCALL_INTERRUPT, _syscall_interrupt);

  ERI_DECLARE_SYMBOL (EN_SIZE, sizeof (struct eri_entry));
}
