#ifndef ERI_ENTRY_H
#define ERI_ENTRY_H

#ifndef __ASSEMBLER__

#include <stdint.h>

struct eri_public_thread_entry
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
};

#endif

#define ERI_SIG_STACK_SIZE	4096

#endif
