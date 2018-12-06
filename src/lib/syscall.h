#ifndef ERI_LIB_SYSCALL_H
#define ERI_LIB_SYSCALL_H

#include <asm/unistd.h>

#include "lib/util.h"
#include "public/comm.h"

#ifndef __ASSEMBLER__
#include <stdint.h>

#define _SYSCALL_NARGS_X(a, b, c, d, e, f, g, h, i, ...) i
#define ERI_SYSCALL_NARGS(...) \
  _SYSCALL_NARGS_X (__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1, 0)

#define _LOAD_ARGS_0()
#define _LOAD_ARGS_1(a1) \
  _LOAD_ARGS_0 () \
  uint64_t __arg1 = (uint64_t) (a1);
#define _LOAD_ARGS_2(a1, a2) \
  _LOAD_ARGS_1 (a1) \
  uint64_t __arg2 = (uint64_t) (a2);
#define _LOAD_ARGS_3(a1, a2, a3) \
  _LOAD_ARGS_2 (a1, a2) \
  uint64_t __arg3 = (uint64_t) (a3);
#define _LOAD_ARGS_4(a1, a2, a3, a4) \
  _LOAD_ARGS_3 (a1, a2, a3) \
  uint64_t __arg4 = (uint64_t) (a4);
#define _LOAD_ARGS_5(a1, a2, a3, a4, a5) \
  _LOAD_ARGS_4 (a1, a2, a3, a4) \
  uint64_t __arg5 = (uint64_t) (a5);
#define _LOAD_ARGS_6(a1, a2, a3, a4, a5, a6) \
  _LOAD_ARGS_5 (a1, a2, a3, a4, a5) \
  uint64_t __arg6 = (uint64_t) (a6);

#define _LOAD_REGS_0
#define _LOAD_REGS_1 \
  _LOAD_REGS_0 \
  register uint64_t _a1 asm ("rdi") = __arg1;
#define _LOAD_REGS_2 \
  _LOAD_REGS_1 \
  register uint64_t _a2 asm ("rsi") = __arg2;
#define _LOAD_REGS_3 \
  _LOAD_REGS_2 \
  register uint64_t _a3 asm ("rdx") = __arg3;
#define _LOAD_REGS_4 \
  _LOAD_REGS_3 \
  register uint64_t _a4 asm ("r10") = __arg4;
#define _LOAD_REGS_5 \
  _LOAD_REGS_4 \
  register uint64_t _a5 asm ("r8") = __arg5;
#define _LOAD_REGS_6 \
  _LOAD_REGS_5 \
  register uint64_t _a6 asm ("r9") = __arg6;

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

#define _SYSCALL_NR(name, nargs, ...) \
  ({ \
    uint64_t __result; \
    _ERS_PASTE (_LOAD_ARGS_, nargs) (__VA_ARGS__) \
    _ERS_PASTE (_LOAD_REGS_, nargs) \
    asm volatile ( \
      "syscall\n\t" \
      : "=a" (__result) \
      : "0" (name) _ERS_PASTE (_SYSCALL_ARGS_, nargs) : "memory", "cc", "r11", "cx" \
    ); \
    __result; \
  })

#define ERI_SYSCALL(name, ...) \
  _SYSCALL_NR (__NR_##name, ERI_SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

#define ERI_SYSCALL_NCS(no, ...) \
  _SYSCALL_NR (no, ERI_SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

#define ERI_SYSCALL_ERROR_P(val) ((val) >= -4095L)

#define ERI_ASSERT_SYSCALL_RES(...) \
  ({								\
    uint64_t _result = ERI_SYSCALL (__VA_ARGS__);		\
    eri_assert (! ERI_SYSCALL_ERROR_P (_result));		\
    _result;							\
  })

#define ERI_ASSERT_SYSCALL(...) \
  (void) ERI_ASSERT_SYSCALL_RES (__VA_ARGS__)

#endif

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

#define ERI_MAP_PRIVATE		0x2
#define ERI_MAP_FIXED		0x10
#define ERI_MAP_ANONYMOUS	0x20
#define ERI_MAP_GROWSDOWN	0x100
#define ERI_MAP_DENYWRITE	0x0800

#define ERI_ARCH_SET_GS	0x1001
#define ERI_ARCH_SET_FS	0x1002
#define ERI_ARCH_GET_FS	0x1003
#define ERI_ARCH_GET_GS	0x1004

#define ERI_S_IRUSR	0400	/* Read by owner.  */
#define ERI_S_IWUSR	0200	/* Write by owner.  */
#define ERI_S_IXUSR	0100	/* Execute by owner.  */
#define ERI_S_IRWXU	(ERI_S_IRUSR | ERI_S_IWUSR | ERI_S_IXUSR)

#define ERI_O_RDONLY	00
#define ERI_O_WRONLY	01
#define ERI_O_CREAT	0100
#define ERI_O_TRUNC	01000

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
#define ERI_SA_RESTORER	0x04000000
#define ERI_SA_ONSTACK	0x08000000
#define ERI_SA_RESTART	0x10000000

#define ERI_SIGINT	2
#define ERI_SIGILL	4
#define ERI_SIGFPE	8
#define ERI_SIGTRAP	5
#define ERI_SIGKILL	9
#define ERI_SIGBUS	10
#define ERI_SIGSEGV	11
#define ERI_SIGSYS	12
#define ERI_SIGCHLD	17
#define ERI_SIGSTOP	19
#define ERI_SIGURG	23
#define ERI_SIGRTMIN	32
#define ERI_SIGRTMAX	64
#define ERI_NSIG	(ERI_SIGRTMAX + 1)

#define ERI_SIG_SETMASK	2
#define ERI_SIG_SETSIZE	(ERI_NSIG / 8)

#ifdef __ASSEMBLER__

#define ERI_SIG_DFL	0
#define ERI_SIG_IGN	1

#define ERI_SS_ONSTACK	1
#define ERI_SS_DISABLE	2

#define ERI_TRAP_TRACE	2

#else

struct eri_timespec
{
  uint64_t tv_sec;
  uint64_t tv_nsec;
};

#if 0
struct eri_stat
{
  uint64_t dev;
  uint64_t ino;
  uint64_t nlink;
  uint32_t mode;
  uint32_t uid;
  uint32_t gid;
  int32_t pad;
  uint64_t rdev;
  int64_t size;
  int64_t blksize;
  int64_t blocks;
  struct eri_timespec atime;
  struct eri_timespec mtime;
  struct eri_timespec ctime;  
};
#endif

#define ERI_SIG_DFL	((void *) 0)
#define ERI_SIG_IGN	((void *) 1)

struct eri_sigset
{
  uint64_t val[16];
};

struct eri_stack
{
  void *sp;
  int32_t flags;
  uint64_t size;
};

struct eri_sigaction
{
  void *act;
  int32_t flags;
  void (*restorer) (void);
  struct eri_sigset mask;
};

struct eri_siginfo
{
  int32_t signo;
  int32_t errno;
  int32_t code;

  uint8_t buf[116];
};

struct eri_mcontext
{
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rbp;
  uint64_t rbx;
  uint64_t rdx;
  uint64_t rax;
  uint64_t rcx;
  uint64_t rsp;
  uint64_t rip;
  uint64_t rflags;

  uint16_t cs;
  uint16_t gs;
  uint16_t fs;
  uint16_t ss;

  uint64_t err;
  uint64_t trapno;
  uint64_t oldmask;
  uint64_t cr2;

  void *fpstate;

  uint64_t reserved[8];
};

struct eri_ucontext
{
  uint64_t flags;
  struct eri_ucontext *link;
  struct eri_stack stack;
  struct eri_mcontext mctx;
  struct eri_sigset sigmask;
};

#define ERI_UCONTEXT_GET_RSP(ctx) \
  (*((uint64_t *) ((ctx)->buf + ERI_UCONTEXT_RSP)))
#define ERI_UCONTEXT_GET_RIP(ctx) \
  (*((uint64_t *) ((ctx)->buf + ERI_UCONTEXT_RSP)))
#define ERI_UCONTEXT_GET_SIGMASK(ctx) \
  ((struct eri_sigset *) ((ctx)->buf + ERI_UCONTEXT_SIGMASK))

void eri_sigreturn (void);

#define eri_sigfillset(set) \
  eri_memset (set, 0xff, sizeof (struct eri_sigset))
#define eri_sigemptyset(set) \
  eri_memset (set, 0, sizeof (struct eri_sigset))

#define _eri_sigword(sig) \
  (((sig) - 1) / (8 * sizeof (uint64_t)))
#define _eri_sigmask(sig) \
  (((uint64_t) 1) << ((sig) - 1) % (8 * sizeof (uint64_t)))

#define eri_sigaddset(set, sig) \
  do {								\
    int32_t _s = sig;						\
    (set)->val[_eri_sigword (_s)] |= _eri_sigmask (_s);		\
  } while (0)
#define eri_sigdelset(set, sig) \
  do {								\
    int32_t _s = sig;						\
    (set)->val[_eri_sigword (_s)] &= ~_eri_sigmask (_s);	\
  } while (0)
#define eri_sigset_p(set, sig) \
  ({ int32_t _s = sig;						\
     (set)->val[_eri_sigword (_s)] & _eri_sigmask (_s); })

#endif

#endif
