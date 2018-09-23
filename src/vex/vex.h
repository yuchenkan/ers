#ifndef VEX_H
#define VEX_H

#include "vex-pub.h"

struct context;

struct vex_rw_ranges
{
  unsigned long naddrs;
  unsigned long nsizes;
  unsigned long *addrs;
  unsigned long *sizes;
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

  struct vex_rw_ranges reads;
  struct vex_rw_ranges writes;
};

#endif
