#ifndef ERI_INIT_LOCAL_H
#define ERI_INIT_LOCAL_H

#include <stdint.h>

struct init_context
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

uint8_t init_context (eri_file_t init, uint64_t start, uint64_t end);
void init (struct eri_rtld_args *rtld);

#endif
