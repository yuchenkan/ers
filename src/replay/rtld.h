#ifndef ERI_REPLAY_RTLD_H
#define ERI_REPLYA_RTLD_H

#include <stdint.h>

#include <compiler.h>
#include <entry.h>

#include <lib/syscall-common.h>

struct eri_replay_rtld_args
{
  const char *path;
  struct eri_sigset sig_mask;

  uint64_t stack_size;
  uint64_t file_buf_size;

  uint64_t buf;
  uint64_t buf_size;
};

eri_noreturn void eri_start (void);

enum
{
#define SIG_HAND_ENUM(chand, hand)	chand,
  ERI_ENTRY_THREAD_ENTRY_SIG_HANDS (SIG_HAND_ENUM)
  SIG_HAND_RETURN_TO_USER
}

#endif
