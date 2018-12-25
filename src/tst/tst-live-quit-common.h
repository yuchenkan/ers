#ifndef TST_TST_LIVE_QUIT_COMMON_H
#define TST_TST_LIVE_QUIT_COMMON_H

#define TST_LIVE_QUIT_STACK_SIZE	(2 * 1024 * 1024)

#ifndef __ASSEMBLER__

#if 0
void *tst_live_quit_get_thread (void);
#endif

extern int32_t tst_live_quit_printf_lock;

#define TST_LIVE_QUIT_YIELD \
  do {									\
    uint8_t _i;								\
    for (_i = 0; _i < 32; ++_i) ERI_ASSERT_SYSCALL (sched_yield);	\
  } while (0)

void tst_live_quit_clone (uint8_t *stack, int32_t *ptid, int32_t *ctid,
			  void (*fn) (void *), void *data);

void tst_live_quit_exit (int32_t status) __attribute__ ((noreturn));
void tst_live_quit_exit_group (int32_t status) __attribute__ ((noreturn));

#endif

#endif
