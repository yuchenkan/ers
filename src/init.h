#ifndef ERI_INIT_H
#define ERI_INIT_H

#include <stdint.h>

struct eri_init_context
{
  uint64_t rbx;
  uint64_t rsp;
  uint64_t rbp;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;

  uint64_t unmap_start;
  uint64_t unmap_size;
};

#endif
