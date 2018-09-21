#ifndef VEX_H
#define VEX_H

#include "vex-pub.h"

struct context;

struct vex_addr_range
{
  unsigned long size;
};

struct vex_context
{
  struct context *ctx;

  unsigned long syscall;
  unsigned long back;

  struct eri_vex_common_context comm;

  unsigned long insts;

  unsigned long ret;
  unsigned long top;

  unsigned long nreads;
  unsigned long *read_starts;
  unsigned long *read_sizes;

  unsigned long nwrites;
  unsigned long *write_starts;
  unsigned long *write_sizes;
};

#endif
