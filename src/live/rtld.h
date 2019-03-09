#ifndef ERI_LIVE_RTLD_H
#define ERI_LIVE_RTLD_H

#include <stdint.h>

#include <lib/syscall.h>

struct eri_auxv;

struct eri_live_rtld_args
{
  uint64_t rdx;
  uint64_t rsp;
  uint64_t rip;

  struct eri_sigset sig_mask;

  char **envp;
  struct eri_auxv *auxv;
  uint64_t page_size;

  uint64_t map_start;
  uint64_t map_end;

  uint64_t buf;
  uint64_t buf_size;
};

#endif
