#ifndef ERI_LIB_SYSCALL_COMMON_H
#define ERI_LIB_SYSCALL_COMMON_H

#include <asm/unistd.h>

#include <lib/util.h>

#define ERI_SYSCALLS(p) \
  p (clone)								\
  p (unshare)								\
  p (kcmp)								\
  p (fork)								\
  p (vfork)								\
  p (setns)								\
									\
  p (set_tid_address)							\
									\
  p (exit)								\
  p (exit_group)							\
									\
  p (wait4)								\
  p (waitid)								\
									\
  p (execve)								\
  p (execveat)								\
  p (ptrace)								\
  p (syslog)								\
  p (seccomp)								\
									\
  p (uname)								\
  p (sysinfo)								\
  p (getcpu)								\
  p (getrandom)								\
									\
  p (setuid)								\
  p (getuid)								\
  p (setgid)								\
  p (getgid)								\
  p (geteuid)								\
  p (getegid)								\
									\
  p (gettid)								\
  p (getpid)								\
  p (getppid)								\
  p (setreuid)								\
  p (setregid)								\
									\
  p (setresuid)								\
  p (getresuid)								\
  p (setresgid)								\
  p (getresgid)								\
									\
  p (setfsuid)								\
  p (setfsgid)								\
									\
  p (setgroups)								\
  p (getgroups)								\
									\
  p (setsid)								\
  p (getsid)								\
  p (setpgid)								\
  p (getpgid)								\
  p (getpgrp)								\
									\
  p (settimeofday)							\
  p (gettimeofday)							\
  p (time)								\
  p (times)								\
  p (adjtimex)								\
									\
  p (clock_settime)							\
  p (clock_gettime)							\
  p (clock_getres)							\
  p (clock_nanosleep)							\
  p (clock_adjtime)							\
									\
  p (nanosleep)								\
									\
  p (alarm)								\
  p (setitimer)								\
  p (getitimer)								\
									\
  p (timer_create)							\
  p (timer_settime)							\
  p (timer_gettime)							\
  p (timer_getoverrun)							\
  p (timer_delete)							\
									\
  p (setrlimit)								\
  p (getrlimit)								\
  p (prlimit64)								\
  p (getrusage)								\
									\
  p (capset)								\
  p (capget)								\
									\
  p (personality)							\
  p (prctl)								\
  p (arch_prctl)							\
									\
  p (quotactl)								\
  p (acct)								\
									\
  p (setpriority)							\
  p (getpriority)							\
  p (sched_yield)							\
  p (sched_setparam)							\
  p (sched_getparam)							\
  p (sched_setscheduler)						\
  p (sched_getscheduler)						\
  p (sched_get_priority_max)						\
  p (sched_get_priority_min)						\
  p (sched_rr_get_interval)						\
  p (sched_setaffinity)							\
  p (sched_getaffinity)							\
  p (sched_setattr)							\
  p (sched_getattr)							\
									\
  p (ioprio_set)							\
  p (ioprio_get)							\
									\
  p (rt_sigprocmask)							\
  p (rt_sigaction)							\
  p (sigaltstack)							\
  p (rt_sigreturn)							\
  p (rt_sigpending)							\
									\
  p (pause)								\
  p (rt_sigtimedwait)							\
  p (rt_sigsuspend)							\
									\
  p (kill)								\
  p (tkill)								\
  p (tgkill)								\
  p (rt_sigqueueinfo)							\
  p (rt_tgsigqueueinfo)							\
									\
  p (restart_syscall)							\
									\
  p (socket)								\
  p (connect)								\
  p (accept)								\
  p (accept4)								\
  p (sendto)								\
  p (recvfrom)								\
  p (sendmsg)								\
  p (sendmmsg)								\
  p (recvmsg)								\
  p (recvmmsg)								\
  p (shutdown)								\
  p (bind)								\
  p (listen)								\
  p (getsockname)							\
  p (getpeername)							\
  p (socketpair)							\
  p (setsockopt)							\
  p (getsockopt)							\
									\
  p (sethostname)							\
  p (setdomainname)							\
									\
  p (bpf)								\
									\
  p (memfd_create)							\
									\
  p (timerfd_create)							\
  p (timerfd_settime)							\
  p (timerfd_gettime)							\
									\
  p (eventfd)								\
  p (eventfd2)								\
									\
  p (signalfd)								\
  p (signalfd4)								\
  p (pipe)								\
  p (pipe2)								\
									\
  p (inotify_init)							\
  p (inotify_init1)							\
  p (inotify_add_watch)							\
  p (inotify_rm_watch)							\
									\
  p (fanotify_init)							\
  p (fanotify_mark)							\
									\
  p (userfaultfd)							\
  p (perf_event_open)							\
									\
  p (open)								\
  p (openat)								\
  p (creat)								\
  p (close)								\
									\
  p (dup)								\
  p (dup2)								\
  p (dup3)								\
									\
  p (name_to_handle_at)							\
  p (open_by_handle_at)							\
									\
  p (fcntl)								\
  p (flock)								\
  p (fadvise64)								\
									\
  p (truncate)								\
  p (ftruncate)								\
									\
  p (select)								\
  p (pselect6)								\
  p (poll)								\
  p (ppoll)								\
									\
  p (epoll_create)							\
  p (epoll_create1)							\
  p (epoll_wait)							\
  p (epoll_pwait)							\
  p (epoll_ctl)								\
									\
  p (read)								\
  p (pread64)								\
  p (readv)								\
  p (preadv)								\
  p (preadv2)								\
  p (write)								\
  p (pwrite64)								\
  p (writev)								\
  p (pwritev)								\
  p (pwritev2)								\
									\
  p (fallocate)								\
									\
  p (fsync)								\
  p (fdatasync)								\
  p (sync_file_range)							\
									\
  p (readahead)								\
  p (sendfile)								\
  p (copy_file_range)							\
  p (splice)								\
  p (vmsplice)								\
  p (tee)								\
									\
  p (io_setup)								\
  p (io_destroy)							\
  p (io_getevents)							\
  p (io_submit)								\
  p (io_cancel)								\
									\
  p (lseek)								\
  p (ioctl)								\
									\
  p (stat)								\
  p (fstat)								\
  p (newfstatat)							\
  p (lstat)								\
  p (access)								\
  p (faccessat)								\
									\
  p (setxattr)								\
  p (fsetxattr)								\
  p (lsetxattr)								\
  p (getxattr)								\
  p (fgetxattr)								\
  p (lgetxattr)								\
									\
  p (listxattr)								\
  p (flistxattr)							\
  p (llistxattr)							\
									\
  p (removexattr)							\
  p (fremovexattr)							\
  p (lremovexattr)							\
									\
  p (getdents)								\
  p (getdents64)							\
									\
  p (getcwd)								\
  p (chdir)								\
  p (fchdir)								\
  p (rename)								\
  p (renameat)								\
  p (renameat2)								\
  p (mkdir)								\
  p (mkdirat)								\
  p (rmdir)								\
									\
  p (link)								\
  p (linkat)								\
  p (unlink)								\
  p (unlinkat)								\
  p (symlink)								\
  p (symlinkat)								\
  p (readlink)								\
  p (readlinkat)							\
									\
  p (mknod)								\
  p (mknodat)								\
									\
  p (umask)								\
									\
  p (chmod)								\
  p (fchmod)								\
  p (fchmodat)								\
									\
  p (chown)								\
  p (fchown)								\
  p (fchownat)								\
  p (lchown)								\
									\
  p (utime)								\
  p (utimes)								\
  p (futimesat)								\
  p (utimensat)								\
									\
  p (ustat)								\
  p (statfs)								\
  p (fstatfs)								\
									\
  p (sysfs)								\
  p (sync)								\
  p (syncfs)								\
									\
  p (mount)								\
  p (umount2)								\
									\
  p (chroot)								\
  p (pivot_root)							\
									\
  p (mmap)								\
  p (mprotect)								\
  p (munmap)								\
  p (mremap)								\
  p (madvise)								\
  p (brk)								\
									\
  p (msync)								\
  p (mincore)								\
  p (mlock)								\
  p (mlock2)								\
  p (mlockall)								\
  p (munlock)								\
  p (munlockall)							\
									\
  p (modify_ldt)							\
  p (swapon)								\
  p (swapoff)								\
									\
  p (futex)								\
  p (set_robust_list)							\
  p (get_robust_list)							\
									\
  p (pkey_mprotect)							\
  p (pkey_alloc)							\
  p (pkey_free)								\
									\
  p (membarrier)							\
									\
  p (mbind)								\
  p (set_mempolicy)							\
  p (get_mempolicy)							\
  p (migrate_pages)							\
  p (move_pages)							\
									\
  p (shmget)								\
  p (shmat)								\
  p (shmctl)								\
  p (shmdt)								\
									\
  p (semget)								\
  p (semop)								\
  p (semtimedop)							\
  p (semctl)								\
									\
  p (msgget)								\
  p (msgsnd)								\
  p (msgrcv)								\
  p (msgctl)								\
									\
  p (mq_open)								\
  p (mq_unlink)								\
  p (mq_timedsend)							\
  p (mq_timedreceive)							\
  p (mq_notify)								\
  p (mq_getsetattr)							\
									\
  p (add_key)								\
  p (request_key)							\
  p (keyctl)								\
									\
  p (vhangup)								\
									\
  p (reboot)								\
  p (kexec_load)							\
  p (kexec_file_load)							\
									\
  p (iopl)								\
  p (ioperm)								\
									\
  p (init_module)							\
  p (finit_module)							\
  p (delete_module)							\
									\
  p (lookup_dcookie)							\
									\
  p (process_vm_readv)							\
  p (process_vm_writev)							\
									\
  p (remap_file_pages) /* deprecated */

#ifndef __ASSEMBLER__
#include <stdint.h>

#define _eri_syscall_nargs_x(a, b, c, d, e, f, g, h, i, ...)	i
#define eri_syscall_nargs(...) \
  _eri_syscall_nargs_x (__VA_ARGS__, 7, 6, 5, 4, 3, 2, 1, 0)

#define _ERI_LOAD_ARGS_0()
#define _ERI_LOAD_ARGS_1(a1) \
  _ERI_LOAD_ARGS_0 ()							\
  uint64_t _arg1 = (uint64_t) (a1);
#define _ERI_LOAD_ARGS_2(a1, a2) \
  _ERI_LOAD_ARGS_1 (a1)							\
  uint64_t _arg2 = (uint64_t) (a2);
#define _ERI_LOAD_ARGS_3(a1, a2, a3) \
  _ERI_LOAD_ARGS_2 (a1, a2)						\
  uint64_t _arg3 = (uint64_t) (a3);
#define _ERI_LOAD_ARGS_4(a1, a2, a3, a4) \
  _ERI_LOAD_ARGS_3 (a1, a2, a3)						\
  uint64_t _arg4 = (uint64_t) (a4);
#define _ERI_LOAD_ARGS_5(a1, a2, a3, a4, a5) \
  _ERI_LOAD_ARGS_4 (a1, a2, a3, a4)					\
  uint64_t _arg5 = (uint64_t) (a5);
#define _ERI_LOAD_ARGS_6(a1, a2, a3, a4, a5, a6) \
  _ERI_LOAD_ARGS_5 (a1, a2, a3, a4, a5)					\
  uint64_t _arg6 = (uint64_t) (a6);

#define _ERI_LOAD_REGS_0
#define _ERI_LOAD_REGS_1 \
  _ERI_LOAD_REGS_0							\
  register uint64_t _a1 asm ("rdi") = _arg1;
#define _ERI_LOAD_REGS_2 \
  _ERI_LOAD_REGS_1							\
  register uint64_t _a2 asm ("rsi") = _arg2;
#define _ERI_LOAD_REGS_3 \
  _ERI_LOAD_REGS_2							\
  register uint64_t _a3 asm ("rdx") = _arg3;
#define _ERI_LOAD_REGS_4 \
  _ERI_LOAD_REGS_3							\
  register uint64_t _a4 asm ("r10") = _arg4;
#define _ERI_LOAD_REGS_5 \
  _ERI_LOAD_REGS_4							\
  register uint64_t _a5 asm ("r8") = _arg5;
#define _ERI_LOAD_REGS_6 \
  _ERI_LOAD_REGS_5							\
  register uint64_t _a6 asm ("r9") = _arg6;

#define _ERI_SYSCALL_ARGS_0
#define _ERI_SYSCALL_ARGS_1		_ERI_SYSCALL_ARGS_0, "r" (_a1)
#define _ERI_SYSCALL_ARGS_2		_ERI_SYSCALL_ARGS_1, "r" (_a2)
#define _ERI_SYSCALL_ARGS_3		_ERI_SYSCALL_ARGS_2, "r" (_a3)
#define _ERI_SYSCALL_ARGS_4		_ERI_SYSCALL_ARGS_3, "r" (_a4)
#define _ERI_SYSCALL_ARGS_5		_ERI_SYSCALL_ARGS_4, "r" (_a5)
#define _ERI_SYSCALL_ARGS_6		_ERI_SYSCALL_ARGS_5, "r" (_a6)

#define eri_syscall_is_error(val)	((uint64_t) (val) >= (uint64_t) -4095L)

#endif

#define ERI_EPERM	-1	/* Operation not permitted */
#define ERI_ENOENT	-2	/* No such file or directory */
#define ERI_ESRCH	-3	/* No such process */
#define ERI_EINTR	-4	/* Interrupted system call */
#define ERI_EIO		-5	/* I/O error */
#define ERI_ENXIO	-6	/* No such device or address */
#define ERI_E2BIG	-7	/* Argument list too long */
#define ERI_ENOEXEC	-8	/* Exec format error */
#define ERI_EBADF	-9	/* Bad file number */
#define ERI_ECHILD	-10	/* No child processes */
#define ERI_EAGAIN	-11	/* Try again */
#define ERI_ENOMEM	-12	/* Out of memory */
#define ERI_EACCES	-13	/* Permission denied */
#define ERI_EFAULT	-14	/* Bad address */
#define ERI_ENOTBLK	-15	/* Block device required */
#define ERI_EBUSY	-16	/* Device or resource busy */
#define ERI_EEXIST	-17	/* File exists */
#define ERI_EXDEV	-18	/* Cross-device link */
#define ERI_ENODEV	-19	/* No such device */
#define ERI_ENOTDIR	-20	/* Not a directory */
#define ERI_EISDIR	-21	/* Is a directory */
#define ERI_EINVAL	-22	/* Invalid argument */
#define ERI_ENFILE	-23	/* File table overflow */
#define ERI_EMFILE	-24	/* Too many open files */
#define ERI_ENOTTY	-25	/* Not a typewriter */
#define ERI_ETXTBSY	-26	/* Text file busy */
#define ERI_EFBIG	-27	/* File too large */
#define ERI_ENOSPC	-28	/* No space left on device */
#define ERI_ESPIPE	-29	/* Illegal seek */
#define ERI_EROFS	-30	/* Read-only file system */
#define ERI_EMLINK	-31	/* Too many links */
#define ERI_EPIPE	-32	/* Broken pipe */
#define ERI_EDOM	-33	/* Math argument out of domain of func */
#define ERI_ERANGE	-34	/* Math result not representable */

#define ERI_ENOSYS	-38	/* Invalid system call number */
#define	ERI_ETIMEDOUT	-110	/* Connection timed out */

#define ERI_FUTEX_WAIT			0
#define ERI_FUTEX_WAKE			1
#define ERI_FUTEX_WAKE_OP		5
#define ERI_FUTEX_WAIT_BITSET		9

#define ERI_FUTEX_PRIVATE_FLAG		128
#define ERI_FUTEX_CLOCK_REALTIME	256
#define ERI_FUTEX_CMD_MASK \
  ~(ERI_FUTEX_PRIVATE_FLAG | ERI_FUTEX_CLOCK_REALTIME)

#define ERI_FUTEX_WAIT_PRIVATE	(ERI_FUTEX_WAIT | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_WAKE_PRIVATE	(ERI_FUTEX_WAKE | ERI_FUTEX_PRIVATE_FLAG)

#define ERI_PROT_READ		0x1
#define ERI_PROT_WRITE		0x2
#define ERI_PROT_EXEC		0x4

#define ERI_MAP_PRIVATE		0x2
#define ERI_MAP_FIXED		0x10
#define ERI_MAP_ANONYMOUS	0x20
#define ERI_MAP_GROWSDOWN	0x100
#define ERI_MAP_DENYWRITE	0x0800

#define ERI_ARCH_SET_GS		0x1001
#define ERI_ARCH_SET_FS		0x1002
#define ERI_ARCH_GET_FS		0x1003
#define ERI_ARCH_GET_GS		0x1004

#define ERI_S_IRUSR		0400	/* Read by owner.  */
#define ERI_S_IWUSR		0200	/* Write by owner.  */
#define ERI_S_IXUSR		0100	/* Execute by owner.  */
#define ERI_S_IRWXU \
  (ERI_S_IRUSR | ERI_S_IWUSR | ERI_S_IXUSR)

#define ERI_O_RDONLY		00
#define ERI_O_WRONLY		01
#define ERI_O_RDWR		02
#define ERI_O_CREAT		0100
#define ERI_O_TRUNC		01000
#define ERI_O_NONBLOCK		04000
#define ERI_O_DIRECT		040000
#define ERI_O_CLOEXEC		02000000

#define ERI_SFD_CLOEXEC		ERI_O_CLOEXEC
#define ERI_SFD_NONBLOCK	ERI_O_NONBLOCK

#define ERI_POLLIN		0x0001

#define ERI_F_GETFL		3
#define ERI_F_SETFL		4

#define ERI_CLONE_VM			0x00000100
#define ERI_CLONE_FS			0x00000200
#define ERI_CLONE_FILES			0x00000400
#define ERI_CLONE_SIGHAND		0x00000800
#define ERI_CLONE_THREAD		0x00010000
#define ERI_CLONE_SYSVSEM		0x00040000
#define ERI_CLONE_SETTLS		0x00080000
#define ERI_CLONE_PARENT_SETTID		0x00100000
#define ERI_CLONE_CHILD_CLEARTID	0x00200000
#define ERI_CLONE_CHILD_SETTID		0x01000000

#define ERI_CLONE_SUPPORTED_FLAGS \
  (ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SIGHAND	\
   | ERI_CLONE_THREAD | ERI_CLONE_SYSVSEM | ERI_CLONE_SETTLS		\
   | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID)

#define ERI_SEEK_SET		0
#define ERI_SEEK_CUR		1
#define ERI_SEEK_END		2

#define ERI_SA_SIGINFO		4
#define ERI_SA_RESTORER		0x04000000
#define ERI_SA_ONSTACK		0x08000000
#define ERI_SA_RESTART		0x10000000
#define ERI_SA_NODEFER		0x40000000
#define ERI_SA_RESETHAND	0x80000000

#define ERI_SI_USER		0
#define ERI_SI_KERNEL		0x80
#define ERI_SI_TKILL		-6

#define ERI_SIGHUP		1
#define ERI_SIGINT		2
#define ERI_SIGQUIT		3
#define ERI_SIGILL		4
#define ERI_SIGTRAP		5
#define ERI_SIGABRT		6
#define ERI_SIGBUS		7
#define ERI_SIGFPE		8
#define ERI_SIGTRAP		5
#define ERI_SIGKILL		9
#define ERI_SIGUSR1		10
#define ERI_SIGSEGV		11
#define ERI_SIGUSR2		12
#define ERI_SIGPIPE		13
#define ERI_SIGALRM		14
#define ERI_SIGTERM		15
#define ERI_SIGSTKFLT		16
#define ERI_SIGCHLD		17
#define ERI_SIGCONT		18
#define ERI_SIGSTOP		19
#define ERI_SIGTSTP		20
#define ERI_SIGTTIN		21
#define ERI_SIGTTOU		22
#define ERI_SIGURG		23
#define ERI_SIGXCPU		24
#define ERI_SIGXFSZ		25
#define ERI_SIGVTALRM		26
#define ERI_SIGPROF		27
#define ERI_SIGWINCH		28
#define ERI_SIGIO		29
#define ERI_SIGPWR		30
#define ERI_SIGSYS		31
#define ERI_SIGRTMIN		32
#define ERI_SIGRTMAX		64
#define ERI_NSIG		(ERI_SIGRTMAX + 1)

#define ERI_SIG_BLOCK		0
#define ERI_SIG_UNBLOCK		1
#define ERI_SIG_SETMASK		2
#define ERI_SIG_SETSIZE		(ERI_NSIG / 8)

#define ERI_SS_ONSTACK		1
#define ERI_SS_DISABLE		2
#define ERI_SS_AUTODISARM	(1U << 31)

#define ERI_SS_FLAG_BITS	ERI_SS_AUTODISARM

#define ERI_MINSIGSTKSZ		2048

#define ERI_TRAP_TRACE		2

#define ERI_PR_SET_PDEATHSIG	1

#define ERI_P_PID		1
#define ERI_P_PGID		2
#define ERI_WEXITED		4

#ifdef __ASSEMBLER__

#define ERI_SIG_DFL		0
#define ERI_SIG_IGN		1

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

struct eri_pollfd
{
  int32_t fd;
  int16_t events;
  int16_t revents;
};

#define ERI_SIG_DFL		((void *) 0)
#define ERI_SIG_IGN		((void *) 1)

struct eri_sigset
{
  uint64_t val[1];
};

#if 0
struct eri_sigmask
{
  uint8_t mask_all;
  struct eri_sigset mask;
};
#endif

struct eri_stack
{
  uint64_t sp;
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
  int32_t sig;
  int32_t errno;
  int32_t code;
  int32_t pad;

  union {
    uint8_t pad1[112];
    struct {
      int32_t pid;
      int32_t uid;
    } kill;
    struct {
      int32_t pid;
      int32_t uid;
      int32_t status;
    } chld;
  };
};

struct eri_signalfd_siginfo {
  int32_t sig;
  int32_t err;
  int32_t code;
  int32_t pid;
  int32_t uid;
  int32_t fd;
  int32_t tid;
  int32_t band;
  int32_t overrun;
  int32_t trapno;
  int32_t status;
  int32_t val;
  uint64_t ptr;
  int64_t utime;
  int64_t stime;
  uint64_t addr;
  uint16_t addr_lsb;
  uint16_t pad2;
  int32_t syscall;
  uint64_t call_addr;
  uint32_t arch;
  uint8_t pad[28];
};

#define eri_si_from_kernel(info)	((info)->code > 0)

#define eri_si_sync(info) \
  ({ const struct eri_siginfo *_info = info;				\
     (_info->sig == ERI_SIGSEGV || _info->sig == ERI_SIGBUS		\
      || _info->sig == ERI_SIGILL || _info->sig == ERI_SIGTRAP		\
      || _info->sig == ERI_SIGFPE || _info->sig == ERI_SIGSYS)		\
     && eri_si_from_kernel (_info); })
#define eri_si_async(info)		(! eri_si_sync (info))

#define eri_si_single_step(info) \
  ({ const struct eri_siginfo *_info = info;				\
     _info->sig == ERI_SIGTRAP && _info->code == ERI_TRAP_TRACE; })

struct eri_fpstate
{
  uint8_t pad[464];
  uint32_t magic;
  uint32_t size;
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

  struct eri_fpstate *fpstate;

  uint64_t reserved[8];
};

struct eri_ucontext
{
  uint64_t flags;
  struct eri_ucontext *link;
  struct eri_stack stack;
  struct eri_mcontext mctx;
  struct eri_sigset sig_mask;
};

struct eri_sigframe
{
  void *restorer;
  struct eri_ucontext ctx;
  struct eri_siginfo info;
};

typedef void (*eri_sig_handler_t) (int32_t, struct eri_siginfo *,
				   struct eri_ucontext *);

#define eri_sig_fill_set(set) \
  eri_memset (set, 0xff, sizeof (struct eri_sigset))
#define eri_sig_empty_set(set) \
  eri_memset (set, 0, sizeof (struct eri_sigset))

#define _eri_sigword(sig)	(((sig) - 1) / 64)
#define _eri_sigmask(sig)	(((uint64_t) 1) << ((sig) - 1) % 64)

#define eri_sig_add_set(set, sig) \
  do {									\
    int32_t _s = sig;							\
    (set)->val[_eri_sigword (_s)] |= _eri_sigmask (_s);			\
  } while (0)
#define eri_sig_del_set(set, sig) \
  do {									\
    int32_t _s = sig;							\
    (set)->val[_eri_sigword (_s)] &= ~_eri_sigmask (_s);		\
  } while (0)
#define eri_sig_set_set(set, sig) \
  ({ int32_t _s = sig;							\
     (set)->val[_eri_sigword (_s)] & _eri_sigmask (_s); })

#define eri_sig_and_set(set, set1) \
  do {									\
    struct eri_sigset *_s = set;					\
    const struct eri_sigset *_s1 = set1;				\
    int _i;								\
    for (_i = 0; _i < eri_length_of (_s->val); ++_i)			\
      _s->val[_i] &= _s1->val[_i];					\
  } while (0)

#define eri_sig_union_set(set, set1) \
  do {									\
    struct eri_sigset *_s = set;					\
    const struct eri_sigset *_s1 = set1;				\
    int _i;								\
    for (_i = 0; _i < eri_length_of (_s->val); ++_i)			\
      _s->val[_i] |= _s1->val[_i];					\
  } while (0)

#define eri_sig_diff_set(set, set1) \
  do {									\
    struct eri_sigset *_s = set;					\
    const struct eri_sigset *_s1 = set1;				\
    int _i;								\
    for (_i = 0; _i < eri_length_of (_s->val); ++_i)			\
      _s->val[_i] &= ~_s1->val[_i];					\
  } while (0)


#if 0
#define _eri_sigset_word_eq(word, set, to, ...) \
  ({									\
    uint64_t _m = ~0;							\
    if (_eri_sigword (ERI_SIGKILL) == (word))				\
      _m &= ~_eri_sigmask (ERI_SIGKILL);				\
    if (_eri_sigword (ERI_SIGSTOP) == (word))				\
      _m &= ~_eri_sigmask (ERI_SIGSTOP);				\
    ((set)->val[word] & _m) == (to (word, ##__VA_ARGS__) & _m);	\
  })

#define _eri_sigset_cmp(set, to, ...) \
  ({									\
    uint8_t _eq = 1;							\
    int32_t _w;								\
    for (_w = 0; _eq && _w < (ERI_NSIG - 1) / 64; ++_w)			\
      _eq = _eri_sigset_word_eq (_w, set, to, ##__VA_ARGS__);		\
    if (_eq && (ERI_NSIG - 1) % 64)					\
      _eq = _eri_sigset_word_eq (_w, set, to, ##__VA_ARGS__);		\
    _eq;								\
  })

#define _eri_sigset_eq_to(word, b)	((b)->val[word])
#define eri_sigset_eq(a, b) \
  ({									\
    const struct eri_sigset *_a = a, *_b = b;				\
    _eri_sigset_cmp (_a, _eri_sigset_eq_to, _b);			\
  })

#define _eri_sigset_full_to(word)	(~0)
#define eri_sigset_full(set) \
  ({									\
    const struct eri_sigset *_s = set;					\
    _eri_sigset_cmp (_s, _eri_sigset_full_to);				\
  })

#define _eri_sigset_empty_to(word)	0
#define eri_sigset_empty(set) \
  ({									\
    const struct eri_sigset *_s = set;					\
    _eri_sigset_cmp (_s, _eri_sigset_empty_to);				\
  })
#endif

struct eri_sys_syscall_args
{
  int32_t nr;
  uint64_t a[6];
  uint64_t result;
};

struct eri_sys_clone_args
{
  int32_t flags;
  uint8_t *stack;
  int32_t *ptid;
  int32_t *ctid;
  void *new_tls;

  void *fn;
  void *a0;
  void *a1;
  void *a2;

  uint64_t result;
};

#endif

#endif
