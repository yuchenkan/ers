#ifndef ERI_SYSCALL_H
#define ERI_SYSCALL_H

#include <asm/unistd.h>

#include "util.h"

#define _SYSCALL_NARGS_X(a, b, c, d, e, f, g, h, i, ...) i
#define ERI_SYSCALL_NARGS(...) \
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
  _SYSCALL_NR (__NR_##name, ERI_SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

#define ERI_SYSCALL_NCS(no, ...) \
  _SYSCALL_NR (no, ERI_SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

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

#define ERI_EINTR	4
#define ERI_EAGAIN	11

#define ERI_FUTEX_WAIT			0
#define ERI_FUTEX_WAKE			1
#define ERI_FUTEX_WAKE_OP		5
#define ERI_FUTEX_WAIT_BITSET		9

#define ERI_FUTEX_PRIVATE_FLAG		128
#define ERI_FUTEX_CLOCK_REALTIME	256
#define ERI_FUTEX_CMD_MASK		~(ERI_FUTEX_PRIVATE_FLAG | ERI_FUTEX_CLOCK_REALTIME)

#define ERI_FUTEX_WAIT_PRIVATE	(ERI_FUTEX_WAIT | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_WAKE_PRIVATE	(ERI_FUTEX_WAKE | ERI_FUTEX_PRIVATE_FLAG)

#define ERI_PROT_READ	0x1
#define ERI_PROT_WRITE	0x2
#define ERI_PROT_EXEC	0x4

#define ERI_MAP_FILE		0
#define ERI_MAP_PRIVATE		0x2
#define ERI_MAP_FIXED		0x10
#define ERI_MAP_ANONYMOUS	0x20
#define ERI_MAP_GROWSDOWN	0x100
#define ERI_MAP_DENYWRITE	0x0800

#define ERI_MAP_COPY		(ERI_MAP_PRIVATE | ERI_MAP_DENYWRITE)

#define ERI_ARCH_SET_GS	0x1001
#define ERI_ARCH_SET_FS	0x1002
#define ERI_ARCH_GET_FS	0x1003
#define ERI_ARCH_GET_GS	0x1004

#define ERI_S_IRWXU	0700

#define ERI_CLONE_VM			0x00000100
#define ERI_CLONE_FS			0x00000200
#define ERI_CLONE_FILES			0x00000400
#define ERI_CLONE_SIGHAND		0x00000800
#define ERI_CLONE_THREAD		0x00010000
#define ERI_CLONE_SYSVSEM		0x00040000
#define ERI_CLONE_SETTLS		0x00080000
#define ERI_CLONE_PARENT_SETTID		0x00100000
#define ERI_CLONE_CHILD_CLEARTID	0x00200000

#define ERI_SEEK_SET	0
#define ERI_SEEK_CUR	1

#define ERI_SA_SIGINFO	4
#define ERI_SA_RESTART	0x10000000
#define ERI_SA_RESTORER	0x04000000

#define ERI_SIG_DFL	((void *) 0)
#define ERI_SIG_IGN	((void *) 1)

#define ERI_SIGINT	2
#define ERI_SIGKILL	9
#define ERI_SIGCHLD	17
#define ERI_SIGSTOP	19
#define ERI_SIGURG	23
#define ERI_NSIG	65

struct eri_sigset
{
  unsigned long val[16];
};

struct eri_sigaction
{
  void *act;
  int flags;
  void (*restorer) (void);
  struct eri_sigset mask;
};

struct eri_siginfo { char buf[128]; };
struct eri_ucontext { char buf[936]; };
#define ERI_UCONTEXT_RIP	168

#define ERI_SIG_SETMASK	2
#define ERI_SIG_SETSIZE	(ERI_NSIG / 8)

void eri_sigreturn (void);

#define eri_sigfillset(set) eri_memset (set, 0xff, sizeof (struct eri_sigset))
#define eri_sigemptyset(set) eri_memset (set, 0, sizeof (struct eri_sigset))

#define _eri_sigword(sig) (((sig) - 1) / (8 * sizeof (unsigned long)))
#define _eri_sigmask(sig) (((unsigned long) 1) << ((sig) - 1) % (8 * sizeof (unsigned long)))

#define eri_sigaddset(set, sig) \
  do {								\
    int __s = sig;						\
    (set)->val[_eri_sigword (__s)] |= _eri_sigmask (__s);	\
  } while (0)
#define eri_sigdelset(set, sig) \
  do {								\
    int __s = sig;						\
    (set)->val[_eri_sigword (__s)] &= ~_eri_sigmask (__s);	\
  } while (0)
#define eri_sigset_p(set, sig) \
  ({ int __s = sig; (set)->val[_eri_sigword (__s)] & _eri_sigmask (__s); })

struct eri_timespec
{
  unsigned long tv_sec;
  unsigned long tv_nsec;
};

#endif
