#ifndef ERI_ENTRY_H
#define ERI_ENTRY_H

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
