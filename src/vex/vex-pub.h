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

struct eri_vex_rw_ranges
{
  size_t n;
  unsigned long *addrs;
  unsigned long *sizes;
};

#define ERI_VEX_BRK_PRE_EXEC	0x1
#define ERI_VEX_BRK_POST_EXEC	0x2
#define ERI_VEX_BRK_EXIT	0x4
#define ERI_VEX_BRK_EXIT_WAIT	0x8
#define ERI_VEX_BRK_EXIT_GROUP	0x10

#define ERI_VEX_BRK_EXIT_MASK \
  (ERI_VEX_BRK_EXIT | ERI_VEX_BRK_EXIT_WAIT | ERI_VEX_BRK_EXIT_GROUP)

struct eri_vex_brk_desc
{
  struct eri_vex_common_context *ctx;
  unsigned long rip;
  size_t length;
  struct eri_vex_rw_ranges *reads;
  struct eri_vex_rw_ranges *writes;

  unsigned long type;

  struct eri_mtpool *pool;
  void *data;
};

typedef void (*eri_vex_proc_break_t) (struct eri_vex_brk_desc *);

struct eri_vex_desc
{
  char *buf;
  size_t size;
  char mmap;

  size_t pagesize;

  const char *path;

  eri_vex_proc_break_t brk;
  unsigned long brk_mask;
  void *brk_data;

  struct eri_vex_common_context comm;
};

void eri_vex_enter (const struct eri_vex_desc *desc);

#endif
