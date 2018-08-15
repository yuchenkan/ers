#ifndef ERI_SYSCALL_H
#define ERI_SYSCALL_H

#include <asm/unistd.h>

#include "util.h"

#define _SYSCALL_NARGS_X(a, b, c, d, e, f, g, h, i, ...) i
#define _SYSCALL_NARGS(...) \
  _SYSCALL_NARGS_X (__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1, 0)

#define _LOAD_ARGS_0()
#define _LOAD_ARGS_1(a1) \
  _LOAD_ARGS_0 () \
  long __arg1 = (long) (a1);
#define _LOAD_ARGS_2(a1, a2) \
  _LOAD_ARGS_1 (a1) \
  long __arg2 = (long) (a2);
#define _LOAD_ARGS_3(a1, a2, a3) \
  _LOAD_ARGS_2 (a1, a2) \
  long __arg3 = (long) (a3);
#define _LOAD_ARGS_4(a1, a2, a3, a4) \
  _LOAD_ARGS_3 (a1, a2, a3) \
  long __arg4 = (long) (a4);
#define _LOAD_ARGS_5(a1, a2, a3, a4, a5) \
  _LOAD_ARGS_4 (a1, a2, a3, a4) \
  long __arg5 = (long) (a5);
#define _LOAD_ARGS_6(a1, a2, a3, a4, a5, a6) \
  _LOAD_ARGS_5 (a1, a2, a3, a4, a5) \
  long __arg6 = (long) (a6);

#define _LOAD_REGS_0
#define _LOAD_REGS_1 \
  _LOAD_REGS_0 \
  register long _a1 asm ("rdi") = __arg1;
#define _LOAD_REGS_2 \
  _LOAD_REGS_1 \
  register long _a2 asm ("rsi") = __arg2;
#define _LOAD_REGS_3 \
  _LOAD_REGS_2 \
  register long _a3 asm ("rdx") = __arg3;
#define _LOAD_REGS_4 \
  _LOAD_REGS_3 \
  register long _a4 asm ("r10") = __arg4;
#define _LOAD_REGS_5 \
  _LOAD_REGS_4 \
  register long _a5 asm ("r8") = __arg5;
#define _LOAD_REGS_6 \
  _LOAD_REGS_5 \
  register long _a6 asm ("r9") = __arg6;

#define _SYSCALL_ARGS_0
#define _SYSCALL_ARGS_1 \
  _SYSCALL_ARGS_0, "r" (_a1)
#define _SYSCALL_ARGS_2 \
  _SYSCALL_ARGS_1, "r" (_a2)
#define _SYSCALL_ARGS_3 \
  _SYSCALL_ARGS_2, "r" (_a3)
#define _SYSCALL_ARGS_4 \
  _SYSCALL_ARGS_3, "r" (_a4)
#define _SYSCALL_ARGS_5 \
  _SYSCALL_ARGS_4, "r" (_a5)
#define _SYSCALL_ARGS_6 \
  _SYSCALL_ARGS_5, "r" (_a6)

#define _CONCAT_X(a, b) a##b
#define _CONCAT(a, b) _CONCAT_X (a, b)

#define _SYSCALL_NR(name, nargs, ...) \
  ({ \
    unsigned long __result; \
    _CONCAT (_LOAD_ARGS_, nargs) (__VA_ARGS__) \
    _CONCAT (_LOAD_REGS_, nargs) \
    asm volatile ( \
      "syscall\n\t" \
      : "=a" (__result) \
      : "0" (name) _CONCAT (_SYSCALL_ARGS_, nargs) : "memory", "cc", "r11", "cx" \
    ); \
    __result; \
  })

#define ERI_SYSCALL(name, ...) \
  _SYSCALL_NR (__NR_##name, _SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

#define ERI_SYSCALL_NCS(no, ...) \
  _SYSCALL_NR (no, _SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

#define ERI_SYSCALL_ERROR_P(val) \
  ((unsigned long) (long) (val) >= -4095L)

#define ERI_ASSERT_SYSCALL_RES(...) \
  ({								\
    unsigned long _result = ERI_SYSCALL (__VA_ARGS__);		\
    eri_assert (! ERI_SYSCALL_ERROR_P (_result));		\
    _result;							\
  })

#define ERI_ASSERT_SYSCALL(...) \
  (void) ERI_ASSERT_SYSCALL_RES (__VA_ARGS__)

#endif
