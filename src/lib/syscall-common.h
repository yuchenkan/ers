#ifndef ERI_LIB_SYSCALL_COMMON_H
#define ERI_LIB_SYSCALL_COMMON_H

#include <asm/unistd.h>

#include <lib/compiler.h>
#include <lib/util.h>

#define ERI_SYSCALLS(p, ...) \
  p (clone, ##__VA_ARGS__)						\
  p (unshare, ##__VA_ARGS__)						\
  p (kcmp, ##__VA_ARGS__)						\
  p (fork, ##__VA_ARGS__)						\
  p (vfork, ##__VA_ARGS__)						\
  p (setns, ##__VA_ARGS__)						\
									\
  p (set_tid_address, ##__VA_ARGS__)					\
									\
  p (exit, ##__VA_ARGS__)						\
  p (exit_group, ##__VA_ARGS__)						\
									\
  p (wait4, ##__VA_ARGS__)						\
  p (waitid, ##__VA_ARGS__)						\
									\
  p (execve, ##__VA_ARGS__)						\
  p (execveat, ##__VA_ARGS__)						\
  p (ptrace, ##__VA_ARGS__)						\
  p (syslog, ##__VA_ARGS__)						\
  p (seccomp, ##__VA_ARGS__)						\
									\
  p (uname, ##__VA_ARGS__)						\
  p (sysinfo, ##__VA_ARGS__)						\
  p (getcpu, ##__VA_ARGS__)						\
  p (getrandom, ##__VA_ARGS__)						\
									\
  p (setuid, ##__VA_ARGS__)						\
  p (getuid, ##__VA_ARGS__)						\
  p (setgid, ##__VA_ARGS__)						\
  p (getgid, ##__VA_ARGS__)						\
  p (geteuid, ##__VA_ARGS__)						\
  p (getegid, ##__VA_ARGS__)						\
									\
  p (gettid, ##__VA_ARGS__)						\
  p (getpid, ##__VA_ARGS__)						\
  p (getppid, ##__VA_ARGS__)						\
  p (setreuid, ##__VA_ARGS__)						\
  p (setregid, ##__VA_ARGS__)						\
									\
  p (setresuid, ##__VA_ARGS__)						\
  p (getresuid, ##__VA_ARGS__)						\
  p (setresgid, ##__VA_ARGS__)						\
  p (getresgid, ##__VA_ARGS__)						\
									\
  p (setfsuid, ##__VA_ARGS__)						\
  p (setfsgid, ##__VA_ARGS__)						\
									\
  p (setgroups, ##__VA_ARGS__)						\
  p (getgroups, ##__VA_ARGS__)						\
									\
  p (setsid, ##__VA_ARGS__)						\
  p (getsid, ##__VA_ARGS__)						\
  p (setpgid, ##__VA_ARGS__)						\
  p (getpgid, ##__VA_ARGS__)						\
  p (getpgrp, ##__VA_ARGS__)						\
									\
  p (settimeofday, ##__VA_ARGS__)					\
  p (gettimeofday, ##__VA_ARGS__)					\
  p (time, ##__VA_ARGS__)						\
  p (times, ##__VA_ARGS__)						\
  p (adjtimex, ##__VA_ARGS__)						\
									\
  p (clock_settime, ##__VA_ARGS__)					\
  p (clock_gettime, ##__VA_ARGS__)					\
  p (clock_getres, ##__VA_ARGS__)					\
  p (clock_nanosleep, ##__VA_ARGS__)					\
  p (clock_adjtime, ##__VA_ARGS__)					\
									\
  p (nanosleep, ##__VA_ARGS__)						\
									\
  p (alarm, ##__VA_ARGS__)						\
  p (setitimer, ##__VA_ARGS__)						\
  p (getitimer, ##__VA_ARGS__)						\
									\
  p (timer_create, ##__VA_ARGS__)					\
  p (timer_settime, ##__VA_ARGS__)					\
  p (timer_gettime, ##__VA_ARGS__)					\
  p (timer_getoverrun, ##__VA_ARGS__)					\
  p (timer_delete, ##__VA_ARGS__)					\
									\
  p (setrlimit, ##__VA_ARGS__)						\
  p (getrlimit, ##__VA_ARGS__)						\
  p (prlimit64, ##__VA_ARGS__)						\
  p (getrusage, ##__VA_ARGS__)						\
									\
  p (capset, ##__VA_ARGS__)						\
  p (capget, ##__VA_ARGS__)						\
									\
  p (personality, ##__VA_ARGS__)					\
  p (prctl, ##__VA_ARGS__)						\
  p (arch_prctl, ##__VA_ARGS__)						\
									\
  p (quotactl, ##__VA_ARGS__)						\
  p (acct, ##__VA_ARGS__)						\
									\
  p (setpriority, ##__VA_ARGS__)					\
  p (getpriority, ##__VA_ARGS__)					\
  p (sched_yield, ##__VA_ARGS__)					\
  p (sched_setparam, ##__VA_ARGS__)					\
  p (sched_getparam, ##__VA_ARGS__)					\
  p (sched_setscheduler, ##__VA_ARGS__)					\
  p (sched_getscheduler, ##__VA_ARGS__)					\
  p (sched_get_priority_max, ##__VA_ARGS__)				\
  p (sched_get_priority_min, ##__VA_ARGS__)				\
  p (sched_rr_get_interval, ##__VA_ARGS__)				\
  p (sched_setaffinity, ##__VA_ARGS__)					\
  p (sched_getaffinity, ##__VA_ARGS__)					\
  p (sched_setattr, ##__VA_ARGS__)					\
  p (sched_getattr, ##__VA_ARGS__)					\
									\
  p (ioprio_set, ##__VA_ARGS__)						\
  p (ioprio_get, ##__VA_ARGS__)						\
									\
  p (rt_sigprocmask, ##__VA_ARGS__)					\
  p (rt_sigaction, ##__VA_ARGS__)					\
  p (sigaltstack, ##__VA_ARGS__)					\
  p (rt_sigreturn, ##__VA_ARGS__)					\
  p (rt_sigpending, ##__VA_ARGS__)					\
									\
  p (pause, ##__VA_ARGS__)						\
  p (rt_sigsuspend, ##__VA_ARGS__)					\
  p (rt_sigtimedwait, ##__VA_ARGS__)					\
									\
  p (kill, ##__VA_ARGS__)						\
  p (tkill, ##__VA_ARGS__)						\
  p (tgkill, ##__VA_ARGS__)						\
  p (rt_sigqueueinfo, ##__VA_ARGS__)					\
  p (rt_tgsigqueueinfo, ##__VA_ARGS__)					\
									\
  p (restart_syscall, ##__VA_ARGS__)					\
									\
  p (socket, ##__VA_ARGS__)						\
  p (connect, ##__VA_ARGS__)						\
  p (accept, ##__VA_ARGS__)						\
  p (accept4, ##__VA_ARGS__)						\
  p (sendto, ##__VA_ARGS__)						\
  p (recvfrom, ##__VA_ARGS__)						\
  p (sendmsg, ##__VA_ARGS__)						\
  p (sendmmsg, ##__VA_ARGS__)						\
  p (recvmsg, ##__VA_ARGS__)						\
  p (recvmmsg, ##__VA_ARGS__)						\
  p (shutdown, ##__VA_ARGS__)						\
  p (bind, ##__VA_ARGS__)						\
  p (listen, ##__VA_ARGS__)						\
  p (getsockname, ##__VA_ARGS__)					\
  p (getpeername, ##__VA_ARGS__)					\
  p (socketpair, ##__VA_ARGS__)						\
  p (setsockopt, ##__VA_ARGS__)						\
  p (getsockopt, ##__VA_ARGS__)						\
									\
  p (sethostname, ##__VA_ARGS__)					\
  p (setdomainname, ##__VA_ARGS__)					\
									\
  p (bpf, ##__VA_ARGS__)						\
									\
  p (memfd_create, ##__VA_ARGS__)					\
									\
  p (timerfd_create, ##__VA_ARGS__)					\
  p (timerfd_settime, ##__VA_ARGS__)					\
  p (timerfd_gettime, ##__VA_ARGS__)					\
									\
  p (eventfd, ##__VA_ARGS__)						\
  p (eventfd2, ##__VA_ARGS__)						\
									\
  p (signalfd, ##__VA_ARGS__)						\
  p (signalfd4, ##__VA_ARGS__)						\
  p (pipe, ##__VA_ARGS__)						\
  p (pipe2, ##__VA_ARGS__)						\
									\
  p (inotify_init, ##__VA_ARGS__)					\
  p (inotify_init1, ##__VA_ARGS__)					\
  p (inotify_add_watch, ##__VA_ARGS__)					\
  p (inotify_rm_watch, ##__VA_ARGS__)					\
									\
  p (fanotify_init, ##__VA_ARGS__)					\
  p (fanotify_mark, ##__VA_ARGS__)					\
									\
  p (userfaultfd, ##__VA_ARGS__)					\
  p (perf_event_open, ##__VA_ARGS__)					\
									\
  p (open, ##__VA_ARGS__)						\
  p (openat, ##__VA_ARGS__)						\
  p (creat, ##__VA_ARGS__)						\
  p (close, ##__VA_ARGS__)						\
									\
  p (dup, ##__VA_ARGS__)						\
  p (dup2, ##__VA_ARGS__)						\
  p (dup3, ##__VA_ARGS__)						\
									\
  p (name_to_handle_at, ##__VA_ARGS__)					\
  p (open_by_handle_at, ##__VA_ARGS__)					\
									\
  p (fcntl, ##__VA_ARGS__)						\
  p (flock, ##__VA_ARGS__)						\
  p (fadvise64, ##__VA_ARGS__)						\
									\
  p (truncate, ##__VA_ARGS__)						\
  p (ftruncate, ##__VA_ARGS__)						\
									\
  p (select, ##__VA_ARGS__)						\
  p (pselect6, ##__VA_ARGS__)						\
  p (poll, ##__VA_ARGS__)						\
  p (ppoll, ##__VA_ARGS__)						\
									\
  p (epoll_create, ##__VA_ARGS__)					\
  p (epoll_create1, ##__VA_ARGS__)					\
  p (epoll_wait, ##__VA_ARGS__)						\
  p (epoll_pwait, ##__VA_ARGS__)					\
  p (epoll_ctl, ##__VA_ARGS__)						\
									\
  p (read, ##__VA_ARGS__)						\
  p (pread64, ##__VA_ARGS__)						\
  p (readv, ##__VA_ARGS__)						\
  p (preadv, ##__VA_ARGS__)						\
  p (preadv2, ##__VA_ARGS__)						\
  p (write, ##__VA_ARGS__)						\
  p (pwrite64, ##__VA_ARGS__)						\
  p (writev, ##__VA_ARGS__)						\
  p (pwritev, ##__VA_ARGS__)						\
  p (pwritev2, ##__VA_ARGS__)						\
									\
  p (fallocate, ##__VA_ARGS__)						\
									\
  p (fsync, ##__VA_ARGS__)						\
  p (fdatasync, ##__VA_ARGS__)						\
  p (sync_file_range, ##__VA_ARGS__)					\
									\
  p (readahead, ##__VA_ARGS__)						\
  p (sendfile, ##__VA_ARGS__)						\
  p (copy_file_range, ##__VA_ARGS__)					\
  p (splice, ##__VA_ARGS__)						\
  p (vmsplice, ##__VA_ARGS__)						\
  p (tee, ##__VA_ARGS__)						\
									\
  p (io_setup, ##__VA_ARGS__)						\
  p (io_destroy, ##__VA_ARGS__)						\
  p (io_getevents, ##__VA_ARGS__)					\
  p (io_submit, ##__VA_ARGS__)						\
  p (io_cancel, ##__VA_ARGS__)						\
									\
  p (lseek, ##__VA_ARGS__)						\
  p (ioctl, ##__VA_ARGS__)						\
									\
  p (stat, ##__VA_ARGS__)						\
  p (fstat, ##__VA_ARGS__)						\
  p (newfstatat, ##__VA_ARGS__)						\
  p (lstat, ##__VA_ARGS__)						\
  p (access, ##__VA_ARGS__)						\
  p (faccessat, ##__VA_ARGS__)						\
									\
  p (setxattr, ##__VA_ARGS__)						\
  p (fsetxattr, ##__VA_ARGS__)						\
  p (lsetxattr, ##__VA_ARGS__)						\
  p (getxattr, ##__VA_ARGS__)						\
  p (fgetxattr, ##__VA_ARGS__)						\
  p (lgetxattr, ##__VA_ARGS__)						\
									\
  p (listxattr, ##__VA_ARGS__)						\
  p (flistxattr, ##__VA_ARGS__)						\
  p (llistxattr, ##__VA_ARGS__)						\
									\
  p (removexattr, ##__VA_ARGS__)					\
  p (fremovexattr, ##__VA_ARGS__)					\
  p (lremovexattr, ##__VA_ARGS__)					\
									\
  p (getdents, ##__VA_ARGS__)						\
  p (getdents64, ##__VA_ARGS__)						\
									\
  p (getcwd, ##__VA_ARGS__)						\
  p (chdir, ##__VA_ARGS__)						\
  p (fchdir, ##__VA_ARGS__)						\
  p (rename, ##__VA_ARGS__)						\
  p (renameat, ##__VA_ARGS__)						\
  p (renameat2, ##__VA_ARGS__)						\
  p (mkdir, ##__VA_ARGS__)						\
  p (mkdirat, ##__VA_ARGS__)						\
  p (rmdir, ##__VA_ARGS__)						\
									\
  p (link, ##__VA_ARGS__)						\
  p (linkat, ##__VA_ARGS__)						\
  p (unlink, ##__VA_ARGS__)						\
  p (unlinkat, ##__VA_ARGS__)						\
  p (symlink, ##__VA_ARGS__)						\
  p (symlinkat, ##__VA_ARGS__)						\
  p (readlink, ##__VA_ARGS__)						\
  p (readlinkat, ##__VA_ARGS__)						\
									\
  p (mknod, ##__VA_ARGS__)						\
  p (mknodat, ##__VA_ARGS__)						\
									\
  p (umask, ##__VA_ARGS__)						\
									\
  p (chmod, ##__VA_ARGS__)						\
  p (fchmod, ##__VA_ARGS__)						\
  p (fchmodat, ##__VA_ARGS__)						\
									\
  p (chown, ##__VA_ARGS__)						\
  p (fchown, ##__VA_ARGS__)						\
  p (fchownat, ##__VA_ARGS__)						\
  p (lchown, ##__VA_ARGS__)						\
									\
  p (utime, ##__VA_ARGS__)						\
  p (utimes, ##__VA_ARGS__)						\
  p (futimesat, ##__VA_ARGS__)						\
  p (utimensat, ##__VA_ARGS__)						\
									\
  p (ustat, ##__VA_ARGS__)						\
  p (statfs, ##__VA_ARGS__)						\
  p (fstatfs, ##__VA_ARGS__)						\
									\
  p (sysfs, ##__VA_ARGS__)						\
  p (sync, ##__VA_ARGS__)						\
  p (syncfs, ##__VA_ARGS__)						\
									\
  p (mount, ##__VA_ARGS__)						\
  p (umount2, ##__VA_ARGS__)						\
									\
  p (chroot, ##__VA_ARGS__)						\
  p (pivot_root, ##__VA_ARGS__)						\
									\
  p (mmap, ##__VA_ARGS__)						\
  p (mprotect, ##__VA_ARGS__)						\
  p (munmap, ##__VA_ARGS__)						\
  p (mremap, ##__VA_ARGS__)						\
  p (madvise, ##__VA_ARGS__)						\
  p (brk, ##__VA_ARGS__)						\
									\
  p (msync, ##__VA_ARGS__)						\
  p (mincore, ##__VA_ARGS__)						\
  p (mlock, ##__VA_ARGS__)						\
  p (mlock2, ##__VA_ARGS__)						\
  p (mlockall, ##__VA_ARGS__)						\
  p (munlock, ##__VA_ARGS__)						\
  p (munlockall, ##__VA_ARGS__)						\
									\
  p (modify_ldt, ##__VA_ARGS__)						\
  p (swapon, ##__VA_ARGS__)						\
  p (swapoff, ##__VA_ARGS__)						\
									\
  p (futex, ##__VA_ARGS__)						\
  p (set_robust_list, ##__VA_ARGS__)					\
  p (get_robust_list, ##__VA_ARGS__)					\
									\
  p (pkey_mprotect, ##__VA_ARGS__)					\
  p (pkey_alloc, ##__VA_ARGS__)						\
  p (pkey_free, ##__VA_ARGS__)						\
									\
  p (membarrier, ##__VA_ARGS__)						\
									\
  p (mbind, ##__VA_ARGS__)						\
  p (set_mempolicy, ##__VA_ARGS__)					\
  p (get_mempolicy, ##__VA_ARGS__)					\
  p (migrate_pages, ##__VA_ARGS__)					\
  p (move_pages, ##__VA_ARGS__)						\
									\
  p (shmget, ##__VA_ARGS__)						\
  p (shmat, ##__VA_ARGS__)						\
  p (shmctl, ##__VA_ARGS__)						\
  p (shmdt, ##__VA_ARGS__)						\
									\
  p (semget, ##__VA_ARGS__)						\
  p (semop, ##__VA_ARGS__)						\
  p (semtimedop, ##__VA_ARGS__)						\
  p (semctl, ##__VA_ARGS__)						\
									\
  p (msgget, ##__VA_ARGS__)						\
  p (msgsnd, ##__VA_ARGS__)						\
  p (msgrcv, ##__VA_ARGS__)						\
  p (msgctl, ##__VA_ARGS__)						\
									\
  p (mq_open, ##__VA_ARGS__)						\
  p (mq_unlink, ##__VA_ARGS__)						\
  p (mq_timedsend, ##__VA_ARGS__)					\
  p (mq_timedreceive, ##__VA_ARGS__)					\
  p (mq_notify, ##__VA_ARGS__)						\
  p (mq_getsetattr, ##__VA_ARGS__)					\
									\
  p (add_key, ##__VA_ARGS__)						\
  p (request_key, ##__VA_ARGS__)					\
  p (keyctl, ##__VA_ARGS__)						\
									\
  p (vhangup, ##__VA_ARGS__)						\
									\
  p (reboot, ##__VA_ARGS__)						\
  p (kexec_load, ##__VA_ARGS__)						\
  p (kexec_file_load, ##__VA_ARGS__)					\
									\
  p (iopl, ##__VA_ARGS__)						\
  p (ioperm, ##__VA_ARGS__)						\
									\
  p (init_module, ##__VA_ARGS__)					\
  p (finit_module, ##__VA_ARGS__)					\
  p (delete_module, ##__VA_ARGS__)					\
									\
  p (lookup_dcookie, ##__VA_ARGS__)					\
									\
  p (process_vm_readv, ##__VA_ARGS__)					\
  p (process_vm_writev, ##__VA_ARGS__)					\
									\
  p (remap_file_pages, ##__VA_ARGS__) /* deprecated */

#define ERI_SYSCALL_TABLE_SIZE	512

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

#define	ERI_EDEADLK	-35	/* Resource deadlock would occur */
#define	ERI_ENAMETOOLONG	-36	/* File name too long */
#define	ERI_ENOLCK	-37	/* No record locks available */
#define ERI_ENOSYS	-38	/* Invalid system call number */
#define ERI_ERESTART	-85	/* Interrupted system call should be restarted */
#define	ERI_AFNOSUPPORT	-97	/* Address family not supported by protocol */
#define	ERI_ETIMEDOUT	-110	/* Connection timed out */
#define	ERI_EINPROGRESS	-115	/* Operation now in progress */

#ifndef __ASSEMBLER__
#include <stdint.h>

#define _ERI_LOAD_ARG(i, v, a) \
  uint64_t ERI_PASTE (_arg, i) = (uint64_t) (v);

#define _ERI_LOAD_REG_0	"rdi"
#define _ERI_LOAD_REG_1	"rsi"
#define _ERI_LOAD_REG_2	"rdx"
#define _ERI_LOAD_REG_3	"r10"
#define _ERI_LOAD_REG_4	"r8"
#define _ERI_LOAD_REG_5	"r9"
#define _ERI_LOAD_REG(i, v, a) \
  register uint64_t ERI_PASTE (_a, i)					\
	asm (ERI_PASTE (_ERI_LOAD_REG_, i)) = ERI_PASTE (_arg, i);

#define _ERI_SYSCALL_ARG(i, v, a)	, "r" (ERI_PASTE (_a, i))

static eri_unused uint8_t
eri_syscall_is_error (uint64_t val)
{
  return val >= (uint64_t) -4095l;
}

static eri_unused uint8_t
eri_syscall_is_ok (uint64_t val)
{
  return ! eri_syscall_is_error (val);
}

static eri_unused uint8_t
eri_syscall_is_non_fault_error (uint64_t val)
{
  return eri_syscall_is_error (val) && val != ERI_EFAULT;
}

static eri_unused uint8_t
eri_syscall_is_fault_or_ok (uint64_t val)
{
  return ! eri_syscall_is_non_fault_error (val);
}

#endif

#define ERI_CLOCK_REALTIME		0
#define ERI_CLOCK_MONOTONIC		1
#define ERI_CLOCK_PROCESS_CPUTIME_ID	2
#define ERI_CLOCK_THREAD_CPUTIME_ID	3
#define ERI_CLOCK_MONOTONIC_RAW		4
#define ERI_CLOCK_REALTIME_COARSE	5
#define ERI_CLOCK_MONOTONIC_COARSE	6
#define ERI_CLOCK_BOOTTIME		7
#define ERI_CLOCK_REALTIME_ALARM	8
#define ERI_CLOCK_BOOTTIME_ALARM	9

/* Flags for use with getrandom.  */
#define ERI_GRND_NONBLOCK	0x01
#define ERI_GRND_RANDOM		0x02

#define ERI_FUTEX_WAIT			0
#define ERI_FUTEX_WAKE			1
#define ERI_FUTEX_FD			2
#define ERI_FUTEX_REQUEUE		3
#define ERI_FUTEX_CMP_REQUEUE		4
#define ERI_FUTEX_WAKE_OP		5
#define ERI_FUTEX_LOCK_PI		6
#define ERI_FUTEX_UNLOCK_PI		7
#define ERI_FUTEX_TRYLOCK_PI		8
#define ERI_FUTEX_WAIT_BITSET		9
#define ERI_FUTEX_WAKE_BITSET		10
#define ERI_FUTEX_WAIT_REQUEUE_PI	11
#define ERI_FUTEX_CMP_REQUEUE_PI	12

#define ERI_FUTEX_PRIVATE_FLAG		128
#define ERI_FUTEX_CLOCK_REALTIME	256
#define ERI_FUTEX_CMD_MASK \
  ~(ERI_FUTEX_PRIVATE_FLAG | ERI_FUTEX_CLOCK_REALTIME)

#define ERI_FUTEX_WAIT_PRIVATE	(ERI_FUTEX_WAIT | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_WAKE_PRIVATE	(ERI_FUTEX_WAKE | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_REQUEUE_PRIVATE \
  (ERI_FUTEX_REQUEUE | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_CMP_REQUEUE_PRIVATE \
  (ERI_FUTEX_CMP_REQUEUE | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_WAKE_OP_PRIVATE \
  (ERI_FUTEX_WAKE_OP | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_LOCK_PI_PRIVATE \
  (ERI_FUTEX_LOCK_PI | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_UNLOCK_PI_PRIVATE \
  (ERI_FUTEX_UNLOCK_PI | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_TRYLOCK_PI_PRIVATE \
  (ERI_FUTEX_TRYLOCK_PI | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_WAIT_BITSET_PRIVATE \
  (ERI_FUTEX_WAIT_BITSET | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_WAKE_BITSET_PRIVATE \
  (ERI_FUTEX_WAKE_BITSET | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_WAIT_REQUEUE_PI_PRIVATE \
  (ERI_FUTEX_WAIT_REQUEUE_PI | ERI_FUTEX_PRIVATE_FLAG)
#define ERI_FUTEX_CMP_REQUEUE_PI_PRIVATE \
  (ERI_FUTEX_CMP_REQUEUE_PI | ERI_FUTEX_PRIVATE_FLAG)

#define ERI_FUTEX_WAITERS	0x80000000
#define ERI_FUTEX_OWNER_DIED	0x40000000
#define ERI_FUTEX_TID_MASK	0x3fffffff
#define ERI_ROBUST_LIST_LIMIT	2048

#define ERI_FUTEX_OP_SET	0	/* *(int *)UADDR2 = OPARG; */
#define ERI_FUTEX_OP_ADD	1	/* *(int *)UADDR2 += OPARG; */
#define ERI_FUTEX_OP_OR		2	/* *(int *)UADDR2 |= OPARG; */
#define ERI_FUTEX_OP_ANDN	3	/* *(int *)UADDR2 &= ~OPARG; */
#define ERI_FUTEX_OP_XOR	4	/* *(int *)UADDR2 ^= OPARG; */
#define ERI_FUTEX_OP_NUM	5

#define ERI_FUTEX_OP_OPARG_SHIFT	8	/* Use (1 << OPARG).  */

#define ERI_FUTEX_OP_CMP_EQ	0	/* if (oldval == CMPARG) wake */
#define ERI_FUTEX_OP_CMP_NE	1	/* if (oldval != CMPARG) wake */
#define ERI_FUTEX_OP_CMP_LT	2	/* if (oldval < CMPARG) wake */
#define ERI_FUTEX_OP_CMP_LE	3	/* if (oldval <= CMPARG) wake */
#define ERI_FUTEX_OP_CMP_GT	4	/* if (oldval > CMPARG) wake */
#define ERI_FUTEX_OP_CMP_GE	5	/* if (oldval >= CMPARG) wake */
#define ERI_FUTEX_OP_CMP_NUM	6

#define ERI_FUTEX_OP(op, op_arg, cmp, cmp_arg) \
  (((op & 0xf) << 28) | ((cmp & 0xf) << 24)				\
   | ((op_arg & 0xfff) << 12) | (cmp_arg & 0xfff))

#define ERI_PROT_READ		0x1
#define ERI_PROT_WRITE		0x2
#define ERI_PROT_EXEC		0x4

#define ERI_MAP_SHARED		0x1
#define ERI_MAP_PRIVATE		0x2
#define ERI_MAP_SHARED_VALIDATE	0x3
#define ERI_MAP_TYPE		0xf
#define ERI_MAP_FIXED		0x10
#define ERI_MAP_ANONYMOUS	0x20
#define ERI_MAP_GROWSDOWN	0x100
#define ERI_MAP_DENYWRITE	0x0800
#define ERI_MAP_STACK		0x20000

#define ERI_MREMAP_MAYMOVE	1
#define ERI_MREMAP_FIXED	2

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
#define ERI_O_DIRECTORY		0200000
#define ERI_O_CLOEXEC		02000000

#define ERI_SFD_CLOEXEC		ERI_O_CLOEXEC
#define ERI_SFD_NONBLOCK	ERI_O_NONBLOCK

/* Sequenced, reliable, connection-based byte streams.  */
#define ERI_SOCK_STREAM	1
/* Connectionless, unreliable datagrams of fixed maximum length.  */
#define ERI_SOCK_DGRAM	2
#define ERI_SOCK_RAW	3	/* Raw protocol interface.  */
#define ERI_SOCK_RDM	4	/* Reliably-delivered messages.  */
/*
 * Sequenced, reliable, connection-based, datagrams of fixed
 * maximum length.
 */
#define ERI_SOCK_SEQPACKET	5
#define ERI_SOCK_DCCP	6	/* Datagram Congestion Control Protocol.  */
/*
 * Linux specific way of getting packets at the dev level.  For writing
 * rarp and other similar things on the user level.
 */
#define ERI_SOCK_PACKET	10

#define ERI_SOCK_CLOEXEC	ERI_O_CLOEXEC
#define ERI_SOCK_NONBLOCK	ERI_O_NONBLOCK

#define ERI_R_OK		4	/* Test for read permission.  */
#define ERI_W_OK		2	/* Test for write permission.  */
#define ERI_X_OK		1	/* Test for execute permission.  */
#define ERI_F_OK		0	/* Test for existence.  */

#define ERI_POLLIN		0x0001
#define ERI_POLLPRI		0x0002
#define ERI_POLLOUT		0x0004

#define ERI_F_DUPFD		0
#define ERI_F_GETFL		3
#define ERI_F_SETFL		4

#define ERI_F_DUPFD_CLOEXEC	1030

#define ERI_UIO_MAXIOV		1024

#define ERI_PATH_MAX		4096

#define ERI_SEEK_SET		0
#define ERI_SEEK_CUR		1
#define ERI_SEEK_END		2

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

#define ERI_PR_SET_PDEATHSIG	1

#define ERI_P_PID		1
#define ERI_P_PGID		2
#define ERI_WEXITED		4

#define ERI_RLIMIT_CPU		0
#define ERI_RLIMIT_FSIZE	1
#define ERI_RLIMIT_DATA		2
#define ERI_RLIMIT_STACK	3
#define ERI_RLIMIT_CORE		4
#define ERI_RLIMIT_RSS		5
#define ERI_RLIMIT_NPROC	6
#define ERI_RLIMIT_NOFILE	7
#define ERI_RLIMIT_MEMLOCK	8
#define ERI_RLIMIT_AS		9
#define ERI_RLIMIT_LOCKS	10
#define ERI_RLIMIT_SIGPENDING	11
#define ERI_RLIMIT_MSGQUEUE	12
#define ERI_RLIMIT_NICE		13
#define ERI_RLIMIT_RTPRIO	14
#define ERI_RLIMIT_RTTIME	15
#define ERI_RLIMIT_NLIMITS	16

#define ERI_RUSAGE_SELF		0
#define ERI_RUSAGE_CHILDREN	-1	/* XXX: children? */
#define ERI_RUSAGE_THREAD	1

#define ERI_PRIO_PROCESS	0	/* WHO is a process ID.  */
#define ERI_PRIO_PGRP		1	/* WHO is a process group ID.  */
#define ERI_PRIO_USER		2	/* WHO is a user ID.  */

/* Protocol families.  */
#define ERI_PF_UNSPEC	0	/* Unspecified.  */
#define ERI_PF_LOCAL	1	/* Local to host (pipes and file-domain).  */
#define ERI_PF_UNIX	ERI_PF_LOCAL /* POSIX name for PF_LOCAL.  */
 /* Another non-standard name for PF_LOCAL.  */
#define ERI_PF_FILE	ERI_PF_LOCAL
#define ERI_PF_INET	2	/* IP protocol family.  */
#define ERI_PF_AX25	3	/* Amateur Radio AX.25.  */
#define ERI_PF_IPX	4	/* Novell Internet Protocol.  */
#define ERI_PF_APPLETALK	5	/* Appletalk DDP.  */
#define ERI_PF_NETROM	6	/* Amateur radio NetROM.  */
#define ERI_PF_BRIDGE	7	/* Multiprotocol bridge.  */
#define ERI_PF_ATMPVC	8	/* ATM PVCs.  */
#define ERI_PF_X25	9	/* Reserved for X.25 project.  */
#define ERI_PF_INET6	10	/* IP version 6.  */
#define ERI_PF_ROSE	11	/* Amateur Radio X.25 PLP.  */
#define ERI_PF_DECnet	12	/* Reserved for DECnet project.  */
#define ERI_PF_NETBEUI	13	/* Reserved for 802.2LLC project.  */
#define ERI_PF_SECURITY	14	/* Security callback pseudo AF.  */
#define ERI_PF_KEY	15	/* PF_KEY key management API.  */
#define ERI_PF_NETLINK	16
#define ERI_PF_ROUTE	ERI_PF_NETLINK /* Alias to emulate 4.4BSD.  */
#define ERI_PF_PACKET	17	/* Packet family.  */
#define ERI_PF_ASH	18	/* Ash.  */
#define ERI_PF_ECONET	19	/* Acorn Econet.  */
#define ERI_PF_ATMSVC	20	/* ATM SVCs.  */
#define ERI_PF_RDS	21	/* RDS sockets.  */
#define ERI_PF_SNA	22	/* Linux SNA Project */
#define ERI_PF_IRDA	23	/* IRDA sockets.  */
#define ERI_PF_PPPOX	24	/* PPPoX sockets.  */
#define ERI_PF_WANPIPE	25	/* Wanpipe API sockets.  */
#define ERI_PF_LLC	26	/* Linux LLC.  */
#define ERI_PF_IB	27	/* Native InfiniBand address.  */
#define ERI_PF_MPLS	28	/* MPLS.  */
#define ERI_PF_CAN	29	/* Controller Area Network.  */
#define ERI_PF_TIPC	30	/* TIPC sockets.  */
#define ERI_PF_BLUETOOTH	31	/* Bluetooth sockets.  */
#define ERI_PF_IUCV	32	/* IUCV sockets.  */
#define ERI_PF_RXRPC	33	/* RxRPC sockets.  */
#define ERI_PF_ISDN	34	/* mISDN sockets.  */
#define ERI_PF_PHONET	35	/* Phonet sockets.  */
#define ERI_PF_IEEE802154	36	/* IEEE 802.15.4 sockets.  */
#define ERI_PF_CAIF	37	/* CAIF sockets.  */
#define ERI_PF_ALG	38	/* Algorithm sockets.  */
#define ERI_PF_NFC	39	/* NFC sockets.  */
#define ERI_PF_VSOCK	40	/* vSockets.  */
#define ERI_PF_KCM	41	/* Kernel Connection Multiplexor.  */
#define ERI_PF_QIPCRTR	42	/* Qualcomm IPC Router.  */
#define ERI_PF_SMC	43	/* SMC sockets.  */
#define ERI_PF_MAX	44	/* For now..  */

/* Address families.  */
#define ERI_AF_UNSPEC	ERI_PF_UNSPEC
#define ERI_AF_LOCAL	ERI_PF_LOCAL
#define ERI_AF_UNIX	ERI_PF_UNIX
#define ERI_AF_FILE	ERI_PF_FILE
#define ERI_AF_INET	ERI_PF_INET
#define ERI_AF_AX25	ERI_PF_AX25
#define ERI_AF_IPX	ERI_PF_IPX
#define ERI_AF_APPLETALK	ERI_PF_APPLETALK
#define ERI_AF_NETROM	ERI_PF_NETROM
#define ERI_AF_BRIDGE	ERI_PF_BRIDGE
#define ERI_AF_ATMPVC	ERI_PF_ATMPVC
#define ERI_AF_X25	ERI_PF_X25
#define ERI_AF_INET6	ERI_PF_INET6
#define ERI_AF_ROSE	ERI_PF_ROSE
#define ERI_AF_DECnet	ERI_PF_DECnet
#define ERI_AF_NETBEUI	ERI_PF_NETBEUI
#define ERI_AF_SECURITY	ERI_PF_SECURITY
#define ERI_AF_KEY	ERI_PF_KEY
#define ERI_AF_NETLINK	ERI_PF_NETLINK
#define ERI_AF_ROUTE	ERI_PF_ROUTE
#define ERI_AF_PACKET	ERI_PF_PACKET
#define ERI_AF_ASH	ERI_PF_ASH
#define ERI_AF_ECONET	ERI_PF_ECONET
#define ERI_AF_ATMSVC	ERI_PF_ATMSVC
#define ERI_AF_RDS	ERI_PF_RDS
#define ERI_AF_SNA	ERI_PF_SNA
#define ERI_AF_IRDA	ERI_PF_IRDA
#define ERI_AF_PPPOX	ERI_PF_PPPOX
#define ERI_AF_WANPIPE	ERI_PF_WANPIPE
#define ERI_AF_LLC	ERI_PF_LLC
#define ERI_AF_IB	ERI_PF_IB
#define ERI_AF_MPLS	ERI_PF_MPLS
#define ERI_AF_CAN	ERI_PF_CAN
#define ERI_AF_TIPC	ERI_PF_TIPC
#define ERI_AF_BLUETOOTH	ERI_PF_BLUETOOTH
#define ERI_AF_IUCV	ERI_PF_IUCV
#define ERI_AF_RXRPC	ERI_PF_RXRPC
#define ERI_AF_ISDN	ERI_PF_ISDN
#define ERI_AF_PHONET	ERI_PF_PHONET
#define ERI_AF_IEEE802154	ERI_PF_IEEE802154
#define ERI_AF_CAIF	ERI_PF_CAIF
#define ERI_AF_ALG	ERI_PF_ALG
#define ERI_AF_NFC	ERI_PF_NFC
#define ERI_AF_VSOCK	ERI_PF_VSOCK
#define ERI_AF_KCM	ERI_PF_KCM
#define ERI_AF_QIPCRTR	ERI_PF_QIPCRTR
#define ERI_AF_SMC	ERI_PF_SMC
#define ERI_AF_MAX	ERI_PF_MAX

/* Socket level values.  Others are defined in the appropriate headers.

   XXX These definitions also should go into the appropriate headers as
   far as they are available.  */
#define ERI_SOL_RAW	255
#define ERI_SOL_DECNET	261
#define ERI_SOL_X25	262
#define ERI_SOL_PACKET	263
#define ERI_SOL_ATM	264	/* ATM layer (cell level).  */
#define ERI_SOL_AAL	265	/* ATM Adaption Layer (packet level).  */
#define ERI_SOL_IRDA	266
#define ERI_SOL_NETBEUI	267
#define ERI_SOL_LLC	268
#define ERI_SOL_DCCP	269
#define ERI_SOL_NETLINK	270
#define ERI_SOL_TIPC	271
#define ERI_SOL_RXRPC	272
#define ERI_SOL_PPPOL2TP	273
#define ERI_SOL_BLUETOOTH	274
#define ERI_SOL_PNPIPE	275
#define ERI_SOL_RDS	276
#define ERI_SOL_IUCV	277
#define ERI_SOL_CAIF	278
#define ERI_SOL_ALG	279
#define ERI_SOL_NFC	280
#define ERI_SOL_KCM	281
#define ERI_SOL_TLS	282

/* Maximum queue length specifiable by listen.  */
#define ERI_SOMAXCONN	128

#define ERI_INADDR_ANY	0

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

#define ERI_SEGV_MAPERR		1
#define ERI_SEGV_ACCERR		2

#define ERI_TRAP_TRACE		2

#ifdef __ASSEMBLER__

#define ERI_SIG_DFL		0
#define ERI_SIG_IGN		1

#else

#include <lib/compiler.h>

struct eri_timespec
{
  int64_t sec;
  int64_t nsec;
};

static eri_unused void
eri_timespec_add (struct eri_timespec *a, struct eri_timespec *b)
{
  a->nsec += b->nsec;
  a->sec += b->sec + a->nsec / 1000000000;
  a->nsec %= 1000000000;
}

static eri_unused void
eri_timespec_add_nsec (struct eri_timespec *t, int64_t n)
{
  t->nsec += n;
  t->sec += t->nsec / 1000000000;
  t->nsec %= 1000000000;
}

struct eri_timeval
{
  int64_t sec;
  int64_t usec;
};

struct eri_tms
{
  int64_t utime;
  int64_t stime;
  int64_t cutime;
  int64_t cstime;
};

struct eri_timex
{
  int32_t mode;
  int64_t offset;
  int64_t freq;
  int64_t maxerror;
  int64_t esterror;
  int32_t status;
  int64_t constant;
  int64_t precision;
  int64_t tolerance;
  struct eri_timeval time;
  int64_t tick;
  int64_t ppsfreq;
  int64_t jitter;
  int32_t shift;
  int64_t stabil;
  int64_t jitcnt;
  int64_t calcnt;
  int64_t errcnt;
  int64_t stbcnt;
  int32_t tai;
};

static eri_unused uint8_t
eri_futex_op_get_op (int32_t op)
{
  return (op >> 28) & 0x7;
}

static eri_unused uint8_t
eri_futex_op_get_cmp (uint32_t op)
{
  return (op >> 24) & 0xf;
}

static eri_unused int32_t
eri_futex_op_get_arg (int32_t op)
{
  uint32_t a = (op << 8) >> 20;
  return eri_futex_op_get_op (op) & ERI_FUTEX_OP_OPARG_SHIFT ? 1 << a : a;
}

static eri_unused int32_t
eri_futex_op_get_cmp_arg (int32_t op)
{
  return (op << 20) >> 20;
}

struct eri_robust_list
{
  struct eri_robust_list *next;
};

struct eri_robust_list_head
{
  struct eri_robust_list list;
  uint64_t futex_offset;
  struct eri_robust_list *list_op_pending;
};

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

struct eri_utsname
{
  char sysname[65];
  char nodename[65];
  char release[65];
  char version[65];
  char machine[65];
  char domainname[65];
};

struct eri_dirent
{
  uint64_t ino;
  int64_t off;
  uint16_t reclen;
  char name[0];
};

struct eri_pollfd
{
  int32_t fd;
  int16_t events;
  int16_t revents;
};

struct eri_iovec
{
  void *base;
  uint64_t len;
};

struct eri_ustat
{
  int32_t tfree;
  uint64_t tinode;
  char fname[6];
  char fpack[6];
};

struct eri_rlimit
{
  uint64_t cur;
  uint64_t max;
};

struct eri_rusage
{
  struct eri_timeval utime;
  struct eri_timeval stime;
  int64_t maxrss;
  int64_t ixrss;
  int64_t idrss;
  int64_t isrss;
  int64_t minflt;
  int64_t majflt;
  int64_t nswap;
  int64_t inblock;
  int64_t oublock;
  int64_t msgsnd;
  int64_t msgrcv;
  int64_t nsignals;
  int64_t nvcsw;
  int64_t nivcsw;
};

struct eri_sockaddr
{
  uint16_t family;
  uint8_t data[14];
};

struct eri_sockaddr_storage
{
  uint16_t family;
  uint8_t padding[128 - sizeof (uint16_t) - sizeof (uint64_t)];
  uint64_t align;
};

struct eri_in_addr
{
  uint32_t addr;
};

struct eri_sockaddr_in
{
  uint16_t family;
  uint16_t port;
  struct eri_in_addr addr;

  uint8_t padding[16 - sizeof (uint16_t) * 2 - sizeof (struct eri_in_addr)];
};

#define ERI_SIG_DFL		((void *) 0)
#define ERI_SIG_IGN		((void *) 1)

typedef uint64_t eri_sigset_t;

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
  eri_sigset_t mask;
};

struct eri_siginfo
{
  int32_t sig;
  int32_t errno;
  int32_t code;
  int32_t pad;

  union
    {
      uint8_t pad1[112];
      struct
	{
	  int32_t pid;
	  int32_t uid;
	} kill;
      struct
	{
	  int32_t pid;
	  int32_t uid;
	  int32_t status;
	} chld;
      struct
	{
	  uint64_t addr;
	} fault;
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

static eri_unused uint8_t
eri_si_sync (const struct eri_siginfo *info)
{
  return (info->sig == ERI_SIGSEGV || info->sig == ERI_SIGBUS
	  || info->sig == ERI_SIGILL || info->sig == ERI_SIGTRAP
	  || info->sig == ERI_SIGFPE || info->sig == ERI_SIGSYS)
	 && eri_si_from_kernel (info);
}
#define eri_si_async(info)		(! eri_si_sync (info))

static eri_unused uint8_t
eri_si_single_step (const struct eri_siginfo *info)
{
  return info->sig == ERI_SIGTRAP && info->code == ERI_TRAP_TRACE;
}

static eri_unused uint8_t
eri_si_access_fault (const struct eri_siginfo *info)
{
  return (info->sig == ERI_SIGSEGV || info->sig == ERI_SIGBUS)
	 && eri_si_from_kernel (info);
}

struct eri_fpstate_base
{
  uint8_t pad[464];
  uint32_t magic;
  uint32_t size;
};

struct eri_fpstate
{
  struct eri_fpstate_base base;
  uint8_t ext[1024];
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
  eri_sigset_t sig_mask;
};

struct eri_sigframe
{
  void *restorer;
  struct eri_ucontext ctx;
  struct eri_siginfo info;
};

typedef void (*eri_sig_handler_t) (int32_t, struct eri_siginfo *,
				   struct eri_ucontext *);

#define eri_sig_fill_set(set) do { *(set) = -1; } while (0)
#define eri_sig_empty_set(set) do { *(set) = 0; } while (0)

#define _eri_sig_mask(sig) (1l << ((sig) - 1))

#define eri_sig_add_set(set, sig) \
  do { *(set) |= _eri_sig_mask (sig); } while (0)
#define eri_sig_del_set(set, sig) \
  do { *(set) &= ~_eri_sig_mask (sig); } while (0)
#define eri_sig_set_set(set, sig) (*(set) & _eri_sig_mask (sig))

#define eri_sig_not_set(set) \
  do { eri_sigset_t *_s = set; *_s = ~*_s; } while (0)
#define eri_sig_and_set(set, set1) do { *(set) &= *(set1); } while (0)
#define eri_sig_or_set(set, set1) do { *(set) |= *(set1); } while (0)
#define eri_sig_nand_set(set, set1) do { *(set) &= ~*(set1); } while (0)

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
