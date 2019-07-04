#ifndef ERI_LIVE_SIGNAL_THREAD_LOCAL_H
#define ERI_LIVE_SIGNAL_THREAD_LOCAL_H

#define SIGNAL_THREAD_STACK_SIZE	(1024 * 1024)
#define SIGNAL_THREAD_SIG_STACK_SIZE	(2 * 4096)

#ifndef __ASSEMBLER__

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/list.h>
#include <lib/syscall-common.h>
#include <lib/printf.h>

#include <common/common.h>

struct eri_live_rtld_args;
struct eri_siginfo;

struct signal_thread_group;
struct eri_live_thread;

struct eri_live_signal_thread
{
  struct signal_thread_group *group;

  uint64_t id;
  struct eri_buf_file log;
  struct eri_buf_file sig_log;

  int32_t alive;

  ERI_LST_NODE_FIELDS (thread)

  struct eri_sigset sig_mask;
  struct eri_siginfo *sig_info;
  struct eri_sig_act sig_act;

  uint64_t event_sig_restart;
  uint64_t event_sig_reset_restart;

  int32_t event_pipe[2];

  eri_aligned16 uint8_t stack[SIGNAL_THREAD_STACK_SIZE];
  eri_aligned16 uint8_t sig_stack[SIGNAL_THREAD_SIG_STACK_SIZE];

  int32_t tid;

  struct eri_live_thread *th;
};

struct eri_live_signal_thread *init_group (
			struct eri_live_rtld_args *rtld_args);
eri_noreturn void start_group (struct eri_live_signal_thread *sig_th);

uint8_t sig_mask_async (struct eri_live_signal_thread *sig_th,
			const struct eri_sigset *mask);

#endif

#endif
