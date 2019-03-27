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

  uint64_t access;
  uint64_t access_fault;

  uint8_t swallow_single_step;

  uint8_t sync_async_trace;
  uint64_t sync_async_trace_steps;

  uint64_t atomic_access_fault;
  uint8_t atomic_ext_return;

  struct thread *th;

  eri_aligned16 uint8_t text[0];
};

eri_noreturn void main (struct thread_context *th_ctx);
void entry (void);

ERI_ENTRY_DECLARE_DO_COPY_USER ()

uint8_t do_read_user (struct thread_context *th_ctx,
		      const void *src, uint64_t size);

void do_atomic_read_user (struct thread_context *th_ctx,
			  uint64_t mem, uint8_t size);
void do_atomic_read_write_user (struct thread_context *th_ctx,
				uint64_t mem, uint8_t size);

void atomic_store (uint8_t size, uint64_t mem, uint64_t val);
void atomic_inc (uint8_t size, uint64_t mem, uint64_t *rflags);
void atomic_dec (uint8_t size, uint64_t mem, uint64_t *rflags);
void atomic_cmpxchg_regs (uint8_t size, uint64_t *rax, uint64_t *rflags,
			  uint64_t old_val);

void start_main (struct thread *th);
uint64_t relax (struct thread *th);

#endif
