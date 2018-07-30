#include <asm/unistd.h>

#define SYSCALL_NARGS_X(a, b, c, d, e, f, g, h, i, ...) i
#define SYSCALL_NARGS(...) \
  SYSCALL_NARGS_X(__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1, 0)

#define LOAD_ARGS_0()
#define LOAD_ARGS_1(a1) \
  LOAD_ARGS_0() \
  long int __arg1 = (long int) (a1);
#define LOAD_ARGS_2(a1, a2) \
  LOAD_ARGS_1(a1) \
  long int __arg2 = (long int) (a2);
#define LOAD_ARGS_3(a1, a2, a3) \
  LOAD_ARGS_2(a1, a2) \
  long int __arg3 = (long int) (a3);
#define LOAD_ARGS_4(a1, a2, a3, a4) \
  LOAD_ARGS_3(a1, a2, a3) \
  long int __arg4 = (long int) (a4);
#define LOAD_ARGS_5(a1, a2, a3, a4, a5) \
  LOAD_ARGS_4(a1, a2, a3, a4) \
  long int __arg5 = (long int) (a5);
#define LOAD_ARGS_6(a1, a2, a3, a4, a5, a6) \
  LOAD_ARGS_5(a1, a2, a3, a4, a5) \
  long int __arg6 = (long int) (a6);

#define LOAD_REGS_0
#define LOAD_REGS_1 \
  LOAD_REGS_0 \
  register long int _a1 asm ("rdi") = __arg1;
#define LOAD_REGS_2 \
  LOAD_REGS_1 \
  register long int _a2 asm ("rsi") = __arg2;
#define LOAD_REGS_3 \
  LOAD_REGS_2 \
  register long int _a3 asm ("rdx") = __arg3;
#define LOAD_REGS_4 \
  LOAD_REGS_3 \
  register long int _a4 asm ("r10") = __arg4;
#define LOAD_REGS_5 \
  LOAD_REGS_4 \
  register long int _a5 asm ("r8") = __arg5;
#define LOAD_REGS_6 \
  LOAD_REGS_5 \
  register long int _a6 asm ("r9") = __arg6;

#define SYSCALL_ARGS_0
#define SYSCALL_ARGS_1 \
  SYSCALL_ARGS_0, "r" (_a1)
#define SYSCALL_ARGS_2 \
  SYSCALL_ARGS_1, "r" (_a2)
#define SYSCALL_ARGS_3 \
  SYSCALL_ARGS_2, "r" (_a3)
#define SYSCALL_ARGS_4 \
  SYSCALL_ARGS_3, "r" (_a4)
#define SYSCALL_ARGS_5 \
  SYSCALL_ARGS_4, "r" (_a5)
#define SYSCALL_ARGS_6 \
  SYSCALL_ARGS_5, "r" (_a6)

#define CONCAT_X(a, b) a ## b
#define CONCAT(a, b) CONCAT_X(a, b)

#define SYSCALL_NR(name, nargs, ...) \
  ({ \
    unsigned long int result; \
    CONCAT(LOAD_ARGS_, nargs)(__VA_ARGS__) \
    CONCAT(LOAD_REGS_, nargs) \
    asm volatile ( \
      "syscall\n\t" \
      : "=a" (result) \
      : "0" (name) CONCAT(SYSCALL_ARGS_, nargs) : "memory", "cc", "r11", "cx" \
    ); \
    result; \
  })

#define SYSCALL(name, ...) \
  SYSCALL_NR(__NR_ ## name, SYSCALL_NARGS(0, ## __VA_ARGS__), ## __VA_ARGS__)

#define SYSCALL_ERROR_P(val) \
  ((unsigned long int) (long int) (val) >= -4095L)
