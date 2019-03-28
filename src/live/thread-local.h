#ifndef ERI_LIVE_THREAD_LOCAL_H
#define ERI_LIVE_THREAD_LOCAL_H

#include <stdint.h>

#include <compiler.h>

#include <entry.h>
#include <common.h>
#include <lib/syscall-common.h>

struct eri_siginfo;

struct atomic_pair
{
  uint64_t first, second;
};

struct thread_context
{
  struct eri_entry_thread_entry ext;
  struct eri_entry_thread_context ctx;

  struct eri_sigset *sig_force_deliver;

  struct eri_sigframe *sig_frame; /* Always zero in user code.  */

  struct eri_ver_sigaction sig_act;
  struct eri_sigframe *sig_act_frame;

  uint64_t access; /* Always zero in user code. */
  uint64_t access_fault;

  uint8_t swallow_single_step;

  struct
    {
      struct eri_entry_extra_registers eregs;
      uint8_t wait_sig; /* Always zero in user code. */
      uint64_t sig_intr; /* Always zero in user code. */
    } syscall;

  struct
    {
      uint64_t access_start;
      uint64_t access_end; /* Always zero in user code.  */
      struct atomic_pair idx;
    } atomic;

  struct eri_live_thread *th;

  eri_aligned16 uint8_t text[0];
};

eri_noreturn void main (void);
void entry (void);

ERI_ENTRY_DECLARE_DO_COPY_USER ()

eri_noreturn void sig_to (void);
eri_noreturn void sig_return (struct eri_sigframe *frame);

uint64_t syscall_intr_syscall (struct thread_context *th_ctx,
			       struct eri_sys_syscall_args *args);

#define SIG_HANDS(p) \
  ERI_ENTRY_THREAD_ENTRY_SIG_HANDS (p)					\
  p (SIG_HAND_ASYNC, sig_hand_async)					\
  p (SIG_HAND_NONE, sig_hand_none)					\
  p (SIG_HAND_SIG_ACTION, sig_hand_sig_action)				\
  p (SIG_HAND_RETURN_TO_USER, sig_hand_return_to_user)			\
  p (SIG_HAND_SYNC_ASYNC_RETURN_TO_USER,				\
     sig_hand_sync_async_return_to_user)				\

enum
{
#define SIG_HAND_ENUM(chand, hand)	chand,
  SIG_HANDS (SIG_HAND_ENUM)
};

void start_main (struct eri_live_thread *th);

eri_noreturn void sig_action (struct eri_live_thread *th);

uint8_t syscall (struct eri_live_thread *th);

void sync_async (struct eri_live_thread *th, uint64_t cnt);
eri_noreturn void sig_restart_sync_async (struct eri_live_thread *th);

uint64_t prepare_atomic (struct eri_live_thread *th,
			 uint64_t access_start, uint64_t access_end);
void complete_atomic (struct eri_live_thread *th, uint64_t old_val);

#endif
