#ifndef TST_TST_LIVE_QUIT_COMMON_H
#define TST_TST_LIVE_QUIT_COMMON_H

#define TST_LIVE_QUIT_STACK_SIZE	(2 * 1024 * 1024)

#ifndef __ASSEMBLER__

#include "lib/syscall.h"

extern int32_t tst_live_quit_printf_lock;

#define TST_LIVE_QUIT_YIELD \
  do {									\
    uint8_t _i;								\
    for (_i = 0; _i < 32; ++_i) ERI_ASSERT_SYSCALL (sched_yield);	\
  } while (0)

struct tst_live_quit_child
{
  int32_t ctid;
  int32_t ptid;
  uint8_t stack[TST_LIVE_QUIT_STACK_SIZE];
};

void tst_live_quit_clone (struct tst_live_quit_child *child,
			  void (*fn) (void *), void *data);

void tst_live_quit_exit (int32_t status) __attribute__ ((noreturn));
void tst_live_quit_exit_group (int32_t status) __attribute__ ((noreturn));

#endif

#endif
