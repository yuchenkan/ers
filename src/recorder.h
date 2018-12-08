#ifndef ERI_RECORDER_H
#define ERI_RECORDER_H

#ifndef __ASSEMBLER__

#include <stdint.h>

struct eri_common_thread
{
  void *internal;

  uint64_t mark;
  uint64_t op;

  uint64_t start;
  uint64_t ret;
  uint64_t cont;

  uint64_t dir;

  uint64_t rbx;
  uint64_t var[2];

  uint64_t thread_entry;
};

#endif

#define ERI_SIG_STACK_SIZE	4096

#endif
