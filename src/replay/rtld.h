#ifndef ERI_REPLAY_RTLD_H
#define ERI_REPLYA_RTLD_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>

struct eri_replay_rtld_args
{
  struct eri_range map_range;
  uint64_t page_size;

  uint8_t debug;

  const char *path;
  const char *conf;
  const char *log;

  uint64_t stack_size;
  uint64_t file_buf_size;

  uint64_t buf;
  uint64_t buf_size;
};

eri_noreturn void eri_start (void);

#endif
