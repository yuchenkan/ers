#ifndef ERI_RECORDER_H
#define ERI_RECORDER_H

#ifndef __ASSEMBLER__

#include <stdint.h>

struct eri_common_thread
{
  uint64_t mark;
  uint64_t op;

  uint64_t start;
  uint64_t ret;
  uint64_t cont;

  uint64_t dir;

  uint64_t rbx;
  uint64_t var[2];

  uint64_t thread_entry;

  void *internal;
};

#endif

#define ERI_STACK_SIZE		(2 * 1024 * 1024)
#define ERI_SIG_STACK_SIZE	4096

#endif
