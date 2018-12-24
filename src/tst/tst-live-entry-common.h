#ifndef TST_TST_LIVE_ENTRY_COMMON_H
#define TST_TST_LIVE_ENTRY_COMMON_H

#include "lib/util.h"

#define TST_ERI_LIVE_NULL_STUBS(...) \
  .align 16;								\
  ERI_GLOBAL_HIDDEN (eri_live_sync_async)				\
  ERI_GLOBAL_HIDDEN (eri_live_restart_sync_async)			\
  ERI_GLOBAL_HIDDEN (eri_live_atomic_hash_mem)				\
  ERI_GLOBAL_HIDDEN (eri_live_atomic_load)				\
  ERI_GLOBAL_HIDDEN (eri_live_atomic_store)				\
  ERI_GLOBAL_HIDDEN (eri_live_atomic_load_store)			\
  __VA_ARGS__								\
.lerror:								\
  ERI_ASSERT_FALSE

#ifndef __ASSEMBLER__

#include <stdint.h>

#include "tst/tst-util.h"

#include "lib/syscall.h"

struct tst_context
{
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rbp;
  uint64_t rsp;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t rip;
  uint64_t rflags;
};

void tst_live_entry (struct tst_context *ctx);

struct eri_live_thread_entry *tst_init_live_thread_entry (
			struct tst_rand *radn, uint8_t *buf, uint8_t *stack,
			uint64_t stack_size, uint8_t *sig_stack);

#define TST_MEQ_NR8		(1 << 1)
#define TST_MEQ_NR9		(1 << 2)
#define TST_MEQ_NR10		(1 << 3)
#define TST_MEQ_NR11		(1 << 4)
#define TST_MEQ_NR12		(1 << 5)
#define TST_MEQ_NR13		(1 << 6)
#define TST_MEQ_NR14		(1 << 7)
#define TST_MEQ_NR15		(1 << 8)
#define TST_MEQ_NRDI		(1 << 9)
#define TST_MEQ_NRSI		(1 << 10)
#define TST_MEQ_NRBP		(1 << 11)
#define TST_MEQ_NRBX		(1 << 12)
#define TST_MEQ_NRDX		(1 << 13)
#define TST_MEQ_NRAX		(1 << 14)
#define TST_MEQ_NRCX		(1 << 15)
#define TST_MEQ_NRSP		(1 << 16)
#define TST_MEQ_NRIP		(1 << 17)
#define TST_MEQ_NRFLAGS		(1 << 18)

void tst_assert_mctx_eq (struct eri_mcontext *ctx1,
			 struct eri_mcontext *ctx2, uint32_t flags);

void tst_sig_step_int_trigger (int32_t sig, struct eri_siginfo *info,
			       struct eri_ucontext *ctx);

void tst_block_all_signals (void);
void tst_unblock_all_signals (void);

struct tst_step
{
  uint8_t stepping	: 1;
  uint32_t trigger;
  uint32_t trigger_steps;
};

int32_t tst_sig_step_int_check (struct tst_step *step, uint64_t rip,
				uint64_t enter, uint64_t leave);

#endif

#endif
