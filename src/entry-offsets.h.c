#define ERI_ENTRY_BUILD_ENTRY_OFFSETS_H /* kill circular dependancy */
#include <entry.h>

#include <lib/util.h>
#include <lib/offset.h>

#define ENTRY_THREAD_CONTEXT_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_ENTRY_THREAD_CONTEXT_, name,		\
		      struct eri_entry_thread_context, member)

#define ERTRY_EXTRA_REGISTERS_OFFSET(name, member) \
  ERI_DECLARE_OFFSET (ERI_ENTRY_EXTRA_REGISTERS_, name,		\
		      struct eri_entry_extra_registers, member)

void
declare (void)
{
  ERI_ENTRY_THREAD_ENTRY_OFFSETS (ERI)

  ENTRY_THREAD_CONTEXT_OFFSET (TOP, top);
  ENTRY_THREAD_CONTEXT_OFFSET (RSP, rsp);

#define ENTRY_THREAD_CONTEXT_SREG_OFFSET(creg, reg) \
  ENTRY_THREAD_CONTEXT_OFFSET (ERI_PASTE (SREGS_, creg), sregs.reg);
  ERI_ENTRY_FOREACH_SREG (ENTRY_THREAD_CONTEXT_SREG_OFFSET)

#define ENTRY_EXTRA_REGISTERS_EREG_OFFSET(creg, reg) \
  ERTRY_EXTRA_REGISTERS_OFFSET (creg, reg);
  ERI_ENTRY_FOREACH_EREG (ENTRY_EXTRA_REGISTERS_EREG_OFFSET)
}
