#ifndef ERI_REPLAY_RTLD_H
#define ERI_REPLYA_RTLD_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/syscall-common.h>

#include <common/entry.h>

struct eri_replay_rtld_args
{
  const char *path;
  uint8_t debug;

  struct eri_sigset sig_mask;

  uint64_t stack_size;
  uint64_t file_buf_size;

  uint64_t buf;
  uint64_t buf_size;
};

eri_noreturn void eri_start (void);

#endif
