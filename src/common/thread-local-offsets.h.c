#include <lib/util.h>
#include <lib/offset.h>
#include <common/thread.h>

#define TE_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (TE_, name, struct eri_thread_entry, member)

#define TE_REG_OFFSET(creg, reg) \
  TE_OFFSET (ERI_PASTE (_REGS_, creg), _regs.reg);

void
declare (void)
{
  TE_OFFSET (_ENTER, _enter);
  TE_OFFSET (_LEAVE, _leave);
  TE_OFFSET (_TH_LEAVE, _th_leave);
  _ERI_FOREACH_GREG (TE_REG_OFFSET)
  TE_REG_OFFSET (RFLAGS, rflags);
  TE_OFFSET (_SIG_PENDING, _sig_pending);
  TE_OFFSET (_TH, _th);
  TE_OFFSET (_STACK, _stack);
  TE_OFFSET (_ENTRY, _entry);
  TE_OFFSET (_SIG_ACTION, _sig_action);

  TE_OFFSET (_ACCESS_RBX, _access.rbx);
  TE_OFFSET (_ACCESS_RSP, _access.rsp);
  TE_OFFSET (_ACCESS_RBP, _access.rbp);
  TE_OFFSET (_ACCESS_R12, _access.r12);
  TE_OFFSET (_ACCESS_R13, _access.r13);
  TE_OFFSET (_ACCESS_R14, _access.r14);
  TE_OFFSET (_ACCESS_R15, _access.r15);
  TE_OFFSET (_ACCESS_RIP, _access.rip);
  TE_OFFSET (_TEST_ACCESS, _test_access);

  TE_OFFSET (_SYSCALL_INTERRUPT, _syscall_interrupt);

  ERI_DECLARE_SYMBOL (TE_SIZE, sizeof (struct eri_thread_entry));
}
