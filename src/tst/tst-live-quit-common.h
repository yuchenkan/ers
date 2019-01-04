#ifndef TST_TST_LIVE_QUIT_COMMON_H
#define TST_TST_LIVE_QUIT_COMMON_H

#define TST_LIVE_QUIT_STACK_SIZE	(2 * 1024 * 1024)

#ifndef __ASSEMBLER__

#include "lib/syscall.h"

extern int32_t tst_live_quit_printf_lock;

struct tst_live_quit_child
{
  int32_t ctid;
  int32_t ptid;
  uint8_t stack[TST_LIVE_QUIT_STACK_SIZE];
};

extern uint8_t tst_live_quit_allow_clone;
extern int32_t tst_live_quit_allow_group;

void tst_live_quit_clone (uint8_t *stack, int32_t *ptid, int32_t *ctid,
			  void (*fn) (void *), void *data);
void tst_live_quit_clone_child (struct tst_live_quit_child *child,
				void (*fn) (void *), void *data);

uint8_t tst_live_quit_multi_threading (void);

void tst_live_quit_exit (int32_t status) __attribute__ ((noreturn));
void tst_live_quit_exit_group (int32_t status) __attribute__ ((noreturn));

#endif

#endif
