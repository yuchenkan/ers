#include <stdint.h>

#include "live-entry.h"

uint8_t eri_live_thread_entry_text_end[1];
uint8_t eri_live_thread_entry_text[1];

void
eri_live_entry_sigaction (int32_t sig, struct eri_siginfo *info,
			  struct eri_ucontext *uctx)
{
  /* TODO */
}

void
eri_live_init_thread_entry (struct eri_live_thread_entry *entry,
		void *thread, uint64_t stack_top, uint64_t stack_size,
		void *sig_stack)
{
  /* TODO */
}

void
eri_live_entry_start (struct eri_live_thread_entry *entry,
		      struct eri_rtld *rtld)
{
  while (1) continue;
  /* TODO */
}

uint8_t
eri_live_entry_do_syscall (uint64_t a0, uint64_t a1, uint64_t a2,
			   uint64_t a3, uint64_t a4, uint64_t a5,
			   struct eri_live_entry_syscall_info *info,
			   struct eri_live_thread_entry *entry)
{
  eri_assert (0);
  return 0;
}

uint8_t
eri_live_entry_clone (struct eri_live_thread_entry *entry,
		      struct eri_live_thread_entry *child_entry,
		      struct eri_live_entry_clone_info *clone_info,
		      struct eri_live_entry_syscall_info *info)
{
  /* TODO */
  return 0;
}

uint64_t
tst_main (void)
{
  return 0;
}
