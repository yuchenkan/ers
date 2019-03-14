#ifndef ERI_REPLAY_THREAD_LOCAL_H
#define ERI_REPLAY_THREAD_LOCAL_H

#include <stdint.h>

#include <compiler.h>
#include <entry.h>

struct thread;

struct thread_context
{
  struct eri_entry_thread_entry ext;
  struct eri_entry_thread_context ctx;
  struct eri_entry_extra_registers eregs;

  uint8_t swallow_single_step;

  uint8_t sync_async_trace;
  uint64_t sync_async_trace_steps;

  uint8_t atomic_ext_return;

  struct thread *th;

  eri_aligned16 uint8_t text[0];
};

eri_noreturn main (struct thread_context *th_ctx);
void entry (void);

void start_main (struct thread *th);
uint64_t relax (struct thread *th);

#endif
