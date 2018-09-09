#ifndef VEX_H
#define VEX_H

#include "vex-pub.h"

struct vex_context
{
  unsigned long syscall;
  unsigned long back;
  unsigned long back_relbr;

  struct eri_common_context comm;

  unsigned long insts;

  unsigned long ret;
  unsigned long top;
};

#endif
