#ifndef TST_RECORDER_H
#define TST_RECORDER_H

#include <public/impl.h>

#include <lib/util.h>
#include <lib/syscall.h>

#define _tst_syscall_0(nr) \
  _tst_syscall_6 (nr, 0, 0, 0, 0, 0, 0)
#define _tst_syscall_1(nr, a0) \
  _tst_syscall_6 (nr, a0, 0, 0, 0, 0, 0)
#define _tst_syscall_2(nr, a0, a1) \
  _tst_syscall_6 (nr, a0, a1, 0, 0, 0, 0)
#define _tst_syscall_3(nr, a0, a1, a2) \
  _tst_syscall_6 (nr, a0, a1, a2, 0, 0, 0)
#define _tst_syscall_4(nr, a0, a1, a2, a3) \
  _tst_syscall_6 (nr, a0, a1, a2, a3, 0, 0)
#define _tst_syscall_5(nr, a0, a1, a2, a3, a4) \
  _tst_syscall_6 (nr, a0, a1, a2, a3, a4, 0)
#define _tst_syscall_6(nr, a0, a1, a2, a3, a4, a5) \
  ({ uint64_t _res;							\
     register uint64_t _a0 asm ("rdi") = (uint64_t) (a0);		\
     register uint64_t _a1 asm ("rsi") = (uint64_t) (a1);		\
     register uint64_t _a2 asm ("rdx") = (uint64_t) (a2);		\
     register uint64_t _a3 asm ("r10") = (uint64_t) (a3);		\
     register uint64_t _a4 asm ("r8") = (uint64_t) (a4);		\
     register uint64_t _a5 asm ("r9") = (uint64_t) (a5);		\
     asm volatile (ERI_STR (_ERS_SYSCALL (1))				\
		   : "=a" (_res)					\
		   : "0" (nr), "r" (_a0), "r" (_a1), "r" (_a2),		\
		     "r" (_a3), "r" (_a4), "r" (_a5)			\
		   : "memory", "cc", "r11", "cx");			\
     _res; })

#define tst_syscall(name, ...) \
  ERI_PASTE (_tst_syscall_,						\
	     eri_syscall_nargs (0, ##__VA_ARGS__)) (__NR_##name,	\
						    ##__VA_ARGS__)

#endif
