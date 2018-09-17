#ifndef VEX_H
#define VEX_H

#include "vex-pub.h"

struct context;

struct vex_context
{
  struct context *ctx;

  unsigned long syscall;
  unsigned long back;

  struct eri_common_context comm;

  unsigned long insts;

  unsigned long ret;
  unsigned long top;
};

#endif
