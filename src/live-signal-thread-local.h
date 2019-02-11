#ifndef ERI_LIVE_SIGNAL_THREAD_LOCAL_H
#define ERI_LIVE_SIGNAL_THREAD_LOCAL_H

#define SIGNAL_THREAD_STACK_SIZE	(1024 * 1024)
#define SIGNAL_THREAD_SIG_STACK_SIZE	(2 * 4096)

#ifndef __ASSEMBLER__

#include <stdint.h>

#include "compiler.h"

#include "lib/list.h"
#include "lib/syscall.h"

struct eri_common_args;
struct eri_rtld_args;
struct eri_siginfo;

struct signal_thread_group;
struct eri_live_thread;

struct eri_live_signal_thread
{
  struct signal_thread_group *group;
  int32_t alive;

  ERI_LST_NODE_FIELDS (thread)

  struct eri_sigset sig_mask;
  struct eri_siginfo *sig_info;
  struct eri_sigaction sig_act;

  uint64_t event_sig_restart;
  uint64_t event_sig_reset_restart;

  int32_t event_pipe[2];

  aligned16 uint8_t stack[SIGNAL_THREAD_STACK_SIZE];
  aligned16 uint8_t sig_stack[SIGNAL_THREAD_SIG_STACK_SIZE];

  int32_t tid;

  struct eri_live_thread *th;
};

noreturn void sig_handler (void);
void sig_handler_frame (struct eri_sigframe *frame);

struct eri_live_signal_thread *init_group (
		struct eri_common_args *args,
		struct eri_rtld_args *rtld_args);
noreturn void start_main (struct eri_live_signal_thread *sig_th);

noreturn uint8_t thread_die (int32_t *alive);

uint8_t sig_mask_async (struct eri_live_signal_thread *sig_th,
			      const struct eri_sigset *mask);

#endif

#endif
