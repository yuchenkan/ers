#ifndef ERI_VEX_H
#define ERI_VEX_H

#include <stddef.h>

#include "lib/malloc.h"

struct eri_vex_xsave
{
  char buf[832];
} __attribute__ ((aligned (64)));

struct eri_vex_common_context
{
  unsigned long rip;

  unsigned long rax;
  unsigned long rcx;
  unsigned long rdx;
  unsigned long rbx;
  unsigned long rsp;
  unsigned long rbp;
  unsigned long rsi;
  unsigned long rdi;
  unsigned long r8;
  unsigned long r9;
  unsigned long r10;
  unsigned long r11;
  unsigned long r12;
  unsigned long r13;
  unsigned long r14;
  unsigned long r15;

  unsigned long rflags;
  unsigned long fsbase;

  struct eri_vex_xsave xsave;
};

struct eri_vex_context
{
  size_t pagesize;

  struct eri_vex_common_context comm;
};

void eri_vex_enter (char *buf, size_t size,
		    const struct eri_vex_context *ctx,
		    const char *path, char mmap);

#endif
