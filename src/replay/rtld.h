#ifndef ERI_REPLAY_RTLD_H
#define ERI_REPLYA_RTLD_H

#include <stdint.h>

#include <compiler.h>

struct eri_replay_rtld_args
{
  const char *path;

  uint64_t buf;
  uint64_t buf_size;
};

eri_noreturn void eri_start (void);

#endif
