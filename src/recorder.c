#include <limits.h>
#include <stdarg.h>
#include <asm/unistd.h>

#include "recorder.h"
#include "recorder-offsets.h"
#include "recorder-common.h"
#include "recorder-common-offsets.h"
#include "analysis.h"
#include "common.h"
#include "daemon.h"

#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/malloc.h"
#include "lib/printf.h"
#include "lib/list.h"
#include "lib/rbtree.h"
#include "lib/lock.h"

#include "vex/vex-pub.h"

#ifdef NO_CHECK
# define NO_CHECK_IPRINTF
#endif

struct lock
{
  int lock;
  eri_file_t file;

  unsigned long ver;
  unsigned long tid;
};

struct daemon
{
  void *p;
  struct eri_loop *loop;
  int ctid;
};

#ifndef NO_CHECK
# define ATOMIC_TYPE(type) \
  struct { struct lock lock; type val; }
#else
# define ATOMIC_TYPE(type) type
#endif

struct thread
{
  unsigned long id;
  int *clear_tid;

  long sys_tid;
  ATOMIC_TYPE (char) exit;

  eri_file_t file;
  eri_file_t log;

  ERI_LST_NODE_FIELDS (thread)

  struct eri_sigset old_set;

  struct eri_analysis_thread *analysis;
};

struct atomic_lock
{
  void *mem;

  struct lock lock;
  ERI_RBT_NODE_FIELDS (atomic, struct atomic_lock)
};

struct sigact_wrap
{
  struct lock lock;

  void *act;
  int flags;
};

struct replay_waker
{
  unsigned long tid;
  ERI_RBT_NODE_FIELDS (replay_waker, struct replay_waker)

  unsigned lock_version;
};

struct replay
{
  char *pool_buf;
  size_t pool_buf_size;
  struct eri_mtpool pool;

  int wakers_lock;
  ERI_RBT_TREE_FIELDS (replay_waker, struct replay_waker)
};

ERI_DEFINE_RBTREE (static, replay_waker, struct replay, struct replay_waker, unsigned long, eri_less_than)

static void
replay_exit (struct replay *replay)
{
  eri_assert (replay->wakers_lock == 0);
  struct replay_waker *rw, *nrw;
  ERI_RBT_FOREACH_SAFE (replay_waker, replay, rw, nrw)
    {
      eri_assert (eri_fprintf (ERI_STDERR, "remove replay thread %lx\n", rw) == 0);
      replay_waker_rbt_remove (replay, rw);
      eri_assert_mtfree (&replay->pool, rw);
    }

  eri_assert (eri_fprintf (ERI_STDERR, "replay used %lu\n", replay->pool.pool.used) == 0);
  eri_assert (eri_fini_pool (&replay->pool.pool) == 0);
}

struct analysis
{
  char *buf;
  size_t buf_size;

  struct eri_mtpool *pool;

  char error;

  struct eri_analysis *analysis;
};

#ifndef NO_CHECK
typedef struct lock ilock_t;
#else
typedef int ilock_t;
#endif

struct internal
{
  const char *path;
  size_t file_buf_size;

  char printf;
  int printf_lock;

  char mode;

  struct thread *main;
  long thread_offset;

  long sys_pid;
  ATOMIC_TYPE (char) exit;

  ATOMIC_TYPE (long) active_lock;

  char *ilock_file_buf;

  ilock_t pool_lock;
  char *pool_buf;
  size_t pool_buf_size;
  struct eri_pool pool;

  struct daemon daemon;

  ilock_t atomics_lock;
  ERI_RBT_TREE_FIELDS (atomic, struct atomic_lock)

  unsigned long thread_id;
  ilock_t threads_lock;
  ERI_LST_LIST_FIELDS (thread)

  struct sigact_wrap sigacts[ERI_NSIG];

  struct lock mmap_lock; /* ensure the mmap syscall order */
  struct lock brk_lock; /* make the brk syscall thread safe */
  unsigned long cur_brk;
#ifndef NO_CHECK
  struct lock clone_lock; /* ensure the clone syscall order */
#endif

  struct replay replay;
  struct analysis analysis;
};

ERI_DEFINE_RBTREE (static, atomic, struct internal, struct atomic_lock, void *, eri_less_than)

ERI_DEFINE_LIST (static, thread, struct internal, struct thread)

#ifndef NO_CHECK
# define INTERNAL_LOCK(internal, lock) &(internal)->lock,
#else
# define INTERNAL_LOCK(...)
#endif

#define INTERNAL_LOCKS(internal) \
{								\
  INTERNAL_LOCK (internal, exit.lock)				\
  INTERNAL_LOCK (internal, active_lock.lock)			\
  INTERNAL_LOCK (internal, pool_lock)				\
  INTERNAL_LOCK (internal, atomics_lock)			\
  INTERNAL_LOCK (internal, threads_lock)			\
  &(internal)->mmap_lock, &(internal)->brk_lock,		\
  INTERNAL_LOCK (internal, clone_lock)				\
}

static void
save_lock (eri_file_t file, unsigned long tid)
{
  eri_assert (eri_fwrite (file, (const char *) &tid, sizeof tid, 0) == 0);
}

static unsigned long
load_lock (eri_file_t file)
{
  unsigned long tid;
  size_t s;
  eri_assert (eri_fread (file, (char *) &tid, sizeof tid, &s) == 0);
  eri_assert (s == 0 || s == sizeof tid);
  return s == 0 ? (unsigned long) -1 : tid;
}

static void
init_lock (struct internal *internal, struct lock *lock, eri_file_t file)
{
  lock->lock = 0;
  lock->file = file;

  if (internal->mode != ERS_LIVE)
    {
      lock->ver = 1;
      lock->tid = load_lock (lock->file);
    }
}

static struct replay_waker *
replay_get_waker (struct replay *replay, unsigned long tid)
{
  eri_lock (&replay->wakers_lock);
  struct replay_waker *rw = replay_waker_rbt_get (replay, &tid, ERI_RBT_EQ);
  if (! rw)
    {
      rw = eri_assert_mtcalloc (&replay->pool, sizeof *rw);
      rw->tid = tid;
      replay_waker_rbt_insert (replay, rw);
    }
  eri_unlock (&replay->wakers_lock);
  return rw;
}

#define ANALYSIS_NONE		0
#define ANALYSIS_ERROR		1
#define ANALYSIS_CLONE		2
#define ANALYSIS_ENTER_SILENCE	3
#define ANALYSIS_LEAVE_SILENCE	4
#define ANALYSIS_LLOCK		5
#define ANALYSIS_LUNLOCK	6

asm ("  .text					\n\
  .align 16					\n\
  .type analysis_break, @function		\n\
analysis_break:					\n\
  ret						\n\
  .size analysis_break, .-analysis_break	\n\
  .previous					\n"
);

void
analysis_break (unsigned long type, ...);

static void
analysis_enter_silence (struct internal *internal)
{
  if (internal->mode == ERS_ANALYSIS)
    analysis_break (ANALYSIS_ENTER_SILENCE);
}

static void
analysis_leave_silence (struct internal *internal)
{
  if (internal->mode == ERS_ANALYSIS)
    analysis_break (ANALYSIS_LEAVE_SILENCE);
}

#define replay_assert(internal, exp) \
  do {							\
    struct internal *__i = internal;			\
    if (exp) break;					\
    eri_assert_lprintf (&__i->printf_lock,		\
      "replay assert failed %u " #exp "\n", __LINE__);	\
    eri_assert (__i->mode != ERS_REPLAY);		\
    analysis_break (ANALYSIS_ERROR);			\
    ERI_ASSERT_SYSCALL (exit_group, 1);			\
  } while (0)

static void
llock (struct internal *internal, unsigned long tid, struct lock *lock)
{
  char mode = internal->mode;
  if (mode != ERS_LIVE)
    {
      struct replay_waker *rw = replay_get_waker (&internal->replay, tid);
      unsigned version = __atomic_load_n (&rw->lock_version, __ATOMIC_RELAXED);
      while (__atomic_load_n (&lock->tid, __ATOMIC_ACQUIRE) != tid)
	{
	  struct eri_timespec to = { mode == ERS_REPLAY ? 2 : 60 };
	  long res = ERI_SYSCALL (futex, &rw->lock_version,
				  ERI_FUTEX_WAIT_PRIVATE, version, &to);
	  replay_assert (internal, ! ERI_SYSCALL_ERROR_P (res) || -res == ERI_EAGAIN);
	  version = __atomic_load_n (&rw->lock_version, __ATOMIC_RELAXED);
	}
    }

  eri_lock (&lock->lock);

  if (mode == ERS_LIVE) save_lock (lock->file, tid);

  if (mode == ERS_ANALYSIS)
    analysis_break (ANALYSIS_LLOCK, &lock->lock, lock->ver);
}

static void
lunlock (struct internal *internal, struct lock *lock, char exit)
{
  char mode = internal->mode;

  if (! exit) eri_unlock (&lock->lock);

  if (mode != ERS_LIVE)
    {
      ++lock->ver;
      if (mode == ERS_ANALYSIS)
	analysis_break (ANALYSIS_LUNLOCK, &lock->lock, lock->ver, exit);

      __atomic_store_n (&lock->tid, load_lock (lock->file), __ATOMIC_RELEASE);
      if (lock->tid != -1)
	{
	  struct replay_waker *rw = replay_get_waker (&internal->replay, lock->tid);
	  __atomic_add_fetch (&rw->lock_version, 1, __ATOMIC_RELAXED);
	  ERI_ASSERT_SYSCALL (futex, &rw->lock_version, ERI_FUTEX_WAKE_PRIVATE, 1);
	}
    }
}

#ifndef NO_CHECK
# define ATOMIC_LOAD(i, t, m) \
  ({							\
    struct internal *__i = i;				\
    unsigned long __t = t;				\
    typeof (m) __m = m;					\
    llock (__i, __t, &__m->lock);			\
    typeof (__m->val) __v = __m->val;			\
    lunlock (__i, &__m->lock, 0);			\
    __v;						\
  })
#else
# define ATOMIC_LOAD(i, t, m) __atomic_load_n (m, __ATOMIC_SEQ_CST)
#endif

#ifndef NO_CHECK
# define ATOMIC_STORE(i, t, m, v) \
  do {							\
    struct internal *__i = i;				\
    unsigned long __t = t;				\
    typeof (m) __m = m;					\
    typeof (v) __v = v;					\
    llock (__i, __t, &__m->lock);			\
    __m->val = __v;					\
    lunlock (__i, &__m->lock, 0);			\
  } while (0)
#else
# define ATOMIC_STORE(i, t, m, v) __atomic_store_n (m, v, __ATOMIC_SEQ_CST)
#endif

#ifndef NO_CHECK
# define ATOMIC_FETCH_ADD(i, t, m, v) \
  ({							\
    struct internal *__i = i;				\
    unsigned long __t = t;				\
    typeof (m) __m = m;					\
    typeof (v) __v = v;					\
    llock (__i, __t, &__m->lock);			\
    typeof (__m->val) __o = __m->val;			\
    __m->val += __v;					\
    lunlock (__i, &__m->lock, 0);			\
    __o;						\
  })
#else
# define ATOMIC_FETCH_ADD(i, t, m, v) __atomic_fetch_add (m, v, __ATOMIC_SEQ_CST)
#endif

#define ATOMIC_FETCH_SUB(i, t, m, v) \
  ATOMIC_FETCH_ADD (i, t, m, -(v))
#define ATOMIC_ADD_FETCH(i, t, m, v) \
  ({ typeof (v) _v = (v); ATOMIC_FETCH_ADD (i, t, m, _v) + _v; })
#define ATOMIC_SUB_FETCH(i, t, m, v) \
  ({ typeof (v) _v = (v); ATOMIC_FETCH_SUB (i, t, m, _v) - _v; })

#ifndef NO_CHECK
# define ATOMIC_COMPARE_EXCHANGE(i, t, m, e, v) \
  ({							\
    struct internal *__i = i;				\
    unsigned long __t = t;				\
    typeof (m) __m = m;					\
    typeof (e) __e = e;					\
    typeof (v) __v = v;					\
    llock (__i, __t, &__m->lock);			\
    char __ex = __m->val == __e;			\
    if (__ex) __m->val = __v;				\
    lunlock (__i, &__m->lock, 0);			\
    __ex;						\
  })
#else
# define ATOMIC_COMPARE_EXCHANGE(i, t, m, e, v) \
  ({											\
    typeof (e) __e = e;									\
    __atomic_compare_exchange_n (m, &__e, v, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);	\
  })
#endif

#ifndef NO_CHECK
# define ilock(i, t, l) llock (i, t, l)
#else
# define ilock(i, t, l) eri_lock (l)
#endif

#ifndef NO_CHECK
# define iunlock(i, l, d) lunlock (i, l, d)
#else
# define iunlock(i, l, d) do { if (! (d)) eri_unlock (l); } while (0)
#endif

static void *
imalloc (struct internal *internal, unsigned long tid, size_t size)
{
  void *p;
  ilock (internal, tid, &internal->pool_lock);
  eri_assert (eri_malloc (&internal->pool, size, &p) == 0);
  iunlock (internal, &internal->pool_lock, 0);
  return p;
}

static void *
icalloc (struct internal *internal, unsigned long tid, size_t size, size_t csize)
{
  void *p = imalloc (internal, tid, size);
  eri_memset (p, 0, csize ? : size);
  return p;
}

static void
ifree (struct internal *internal, unsigned long tid, void *p)
{
  if (! p) return;
  ilock (internal, tid, &internal->pool_lock);
  eri_assert (eri_free (&internal->pool, p) == 0);
  iunlock (internal, &internal->pool_lock, 0);
}

static void
iprintf (struct internal *internal, eri_file_t tlog, const char *fmt, ...)
{
#ifndef NO_CHECK_IPRINTF
  va_list arg;
  if (tlog)
    {
      va_start (arg, fmt);
      eri_assert (eri_vfprintf (tlog, fmt, arg) == 0);
      va_end (arg);
    }

  if (internal->printf)
    {
      va_start (arg, fmt);
      eri_assert (eri_vlprintf (&internal->printf_lock, fmt, arg) == 0);
      va_end (arg);
    }
#endif
}

/* 0 for MARK_NONE */
#define MARK_THREAD_ACTIVE	1
#define MARK_THREAD_SIGNAL	2
#define MARK_THREAD_SYSCALL	3

static void
check_syscall (struct internal *internal, eri_file_t file, int nr)
{
  if (internal->mode == ERS_LIVE)
    {
      eri_save_mark (file, MARK_THREAD_SYSCALL);
      eri_assert (eri_fwrite (file, (const char *) &nr, sizeof nr, 0) == 0);
    }
  else
    {
      replay_assert (internal, eri_load_mark (file) == MARK_THREAD_SYSCALL);
      int t;
      eri_assert (eri_fread (file, (char *) &t, sizeof t, 0) == 0);
      replay_assert (internal, nr == t);
    }
}

static void
save_result (eri_file_t file, long res)
{
  eri_assert (eri_fwrite (file, (const char *) &res, sizeof res, 0) == 0);
}

static long
load_result (eri_file_t file)
{
  long res;
  eri_assert (eri_fread (file, (char *) &res, sizeof res, 0) == 0);
  return res;
}

#define SYSCALL_REC_RES(mode, file, nr, ...) \
  ({									\
    long __res;								\
    if (mode == ERS_LIVE)						\
      {									\
	__res = ERI_SYSCALL_NCS (nr, ##__VA_ARGS__);			\
	save_result (file, __res);					\
      }									\
    else __res = load_result (file);					\
    __res;								\
  })

#define SYSCALL_CHECK_RES(mode, file, nr, ...) \
  ({									\
    long __res;								\
    __res = ERI_SYSCALL_NCS (nr, ##__VA_ARGS__);			\
    if (mode == ERS_LIVE) save_result (file, __res);			\
    else eri_assert (__res == load_result (file));			\
    __res;								\
  })

static struct thread *
alloc_thread (struct internal *internal, unsigned long tid,
	      int *ctid, void *tp)
{
  size_t thread_size = eri_size_of (struct thread, 16);
  size_t buf_size = internal->file_buf_size;

  struct thread *th = icalloc (internal, tid,
			       thread_size + buf_size * 3, sizeof *th);

  if (internal->mode == ERS_LIVE)
    th->id = __atomic_fetch_add (&internal->thread_id, 1, __ATOMIC_RELAXED);

  th->clear_tid = ctid;
  return th;
}

static void
save_signal (eri_file_t file, int sig, const struct eri_siginfo *info,
	     const struct eri_ucontext *ucontext)
{
  eri_assert (eri_fwrite (file, (const char *) &sig, sizeof sig, 0) == 0);
  eri_assert (eri_fwrite (file, (const char *) info, sizeof *info, 0) == 0);
  eri_assert (eri_fwrite (file, (const char *) ucontext, sizeof *ucontext, 0) == 0);
}

static void
load_signal (eri_file_t file, int *sig, struct eri_siginfo *info,
	     struct eri_ucontext *ucontext)
{
  eri_assert (eri_fread (file, (char *) sig, sizeof *sig, 0) == 0);
  eri_assert (eri_fread (file, (char *) info, sizeof *info, 0) == 0);
  eri_assert (eri_fread (file, (char *) ucontext, sizeof *ucontext, 0) == 0);
}

static void
start_thread (struct internal *internal, struct thread *th)
{
  size_t thread_size = eri_size_of (struct thread, 16);
  size_t buf_size = internal->file_buf_size;

  char mode = internal->mode;
  const char *path = internal->path;

  unsigned long tid = th->id;

#ifndef NO_CHECK
  eri_file_t lfile = eri_open_path (path, "thread-lock-",
    ERI_OPEN_WITHID | (mode != ERS_LIVE) * ERI_OPEN_READ,
    tid, (char *) th + thread_size, buf_size);
  init_lock (internal, &th->exit.lock, lfile);
#endif

  th->file = eri_open_path (path, "thread-",
    ERI_OPEN_WITHID | (mode != ERS_LIVE) * ERI_OPEN_READ,
    tid, (char *) th + thread_size + buf_size, buf_size);

  th->log = eri_open_path (path,
    mode == ERS_LIVE ? "record-log-" : "replay-log-", ERI_OPEN_WITHID,
    tid, (char *) th + thread_size + 2 * buf_size, buf_size);

  if (mode == ERS_LIVE)
    th->sys_tid = ERI_ASSERT_SYSCALL_RES (gettid);

  iprintf (internal, th->log, "init_thread %lu\n", tid);

  ilock (internal, tid, &internal->threads_lock);
  thread_lst_append (internal, th);
  iunlock (internal, &internal->threads_lock, 0);
}

static void
fini_thread (struct internal *internal, struct thread *th)
{
  ilock (internal, th->id, &internal->threads_lock);
  thread_lst_remove (internal, th);
  iunlock (internal, &internal->threads_lock, 0);

  iprintf (internal, th->log, "fini_thread %lu\n", th->id);
  eri_assert (eri_fclose (th->log) == 0);
  eri_assert (eri_fclose (th->file) == 0);
#ifndef NO_CHECK
  eri_assert (eri_fclose (th->exit.lock.file) == 0);
#endif
  ifree (internal, th->id, th);
}

static void
block_signals (struct eri_sigset *old_set)
{
  struct eri_sigset set;
  eri_sigfillset (&set);
  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK, &set, old_set, ERI_SIG_SETSIZE);
}

static void
restore_signals (const struct eri_sigset *old_set)
{
  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK, old_set, 0, ERI_SIG_SETSIZE);
}

#define ACQUIRE_NORMAL	0
#define ACQUIRE_CLONE	1
#define ACQUIRE_EXIT	2
#define ACQUIRE_ASYNC	3
#define ACQUIRE_INIT	4

static void
acquire_thread (struct internal *internal, struct thread *th, char type, ...)
{
  char mode = internal->mode;

  analysis_enter_silence (internal);

  if (mode == ERS_LIVE)
    {
      block_signals (&th->old_set);
      eri_save_mark (th->file, type == ACQUIRE_ASYNC
			       ? MARK_THREAD_SIGNAL : MARK_THREAD_ACTIVE);
    }

  if (type == ACQUIRE_CLONE || type == ACQUIRE_EXIT)
    {
      int v = 1;
      if (type == ACQUIRE_CLONE)
	{
	  va_list arg;
	  va_start (arg, type);
	  v = va_arg (arg, int);
	  va_end (arg);
	}

      if (ATOMIC_ADD_FETCH (internal, th->id, &internal->active_lock, v) <= 0)
	{
	  if (mode == ERS_LIVE) restore_signals (&th->old_set);
	  while (1) continue;
	}
    }
}

static void sigaction (struct internal *internal, int sig,
		       struct eri_siginfo *info, void *ucontext);

static void
release_thread (struct internal *internal, unsigned long th_arg, char type, ...)
{
  char mode = internal->mode;

  if (type == ACQUIRE_CLONE || type == ACQUIRE_EXIT)
    {
      int v = 1;
      if (type == ACQUIRE_CLONE)
	{
	  va_list arg;
	  va_start (arg, type);
	  v = va_arg (arg, int);
	  va_end (arg);
	}

      eri_assert (ATOMIC_SUB_FETCH (internal,
	type == ACQUIRE_EXIT ? th_arg : ((struct thread *) th_arg)->id,
	&internal->active_lock, v) >= 0);
    }

  if (type == ACQUIRE_EXIT) return;

  struct thread *th = (struct thread *) th_arg;

  if (mode != ERS_LIVE)
    {
      char mk = eri_load_mark (th->file);

      replay_assert (internal,
		     mk == MARK_THREAD_SIGNAL || mk == MARK_THREAD_ACTIVE);

      if (mk == MARK_THREAD_SIGNAL)
	{
	  int sig;
	  struct eri_siginfo info;
	  struct eri_ucontext ucontext;
	  load_signal (th->file, &sig, &info, &ucontext);
	  sigaction (internal, sig, &info, &ucontext);
	}
    }

  if (type == ACQUIRE_INIT) return;

  if (mode == ERS_LIVE)
    restore_signals (&th->old_set);

  analysis_leave_silence (internal);
}

#define SYSCALL_REC_IRES(internal, th, nr, ...) \
  ({									\
    long __res = 0;							\
    release_thread (internal, (unsigned long) th, ACQUIRE_NORMAL);	\
									\
    if ((internal)->mode == ERS_LIVE)					\
      __res = ERI_SYSCALL_NCS (nr, ##__VA_ARGS__);			\
									\
    acquire_thread (internal, th, ACQUIRE_NORMAL);			\
    if ((internal)->mode == ERS_LIVE)					\
      save_result ((th)->file, __res);					\
    else __res = load_result ((th)->file);				\
    __res;								\
  })

asm ("  .text						\n\
  .align 16						\n\
  .type set_context, @function				\n\
set_context:						\n\
  .cfi_startproc					\n\
  movq	%rbx, (%rdi)					\n\
  movq	%rbp, 8(%rdi)					\n\
  movq	%r12, 16(%rdi)					\n\
  movq	%r13, 24(%rdi)					\n\
  movq	%r14, 32(%rdi)					\n\
  movq	%r15, 40(%rdi)					\n\
							\n\
  movq	%rdi, 48(%rdi)					\n\
  movq	%rsi, 56(%rdi)					\n\
  movq	%rdx, 64(%rdi)					\n\
  movq	%rcx, 72(%rdi)					\n\
  movq	%r8, 80(%rdi)					\n\
  movq	%r9, 88(%rdi)					\n\
							\n\
  movq	(%rsp), %rcx					\n\
  movq	%rcx, 96(%rdi)		/* %rip */		\n\
  leaq	8(%rsp), %rcx					\n\
  movq	%rcx, 104(%rdi)		/* %rsp */		\n\
							\n\
  leaq	112(%rdi), %rcx					\n\
  fnstenv	(%rcx)					\n\
  fldenv	(%rcx)					\n\
  stmxcsr	136(%rdi)				\n\
							\n\
  movb	$" _ERS_STR (ERS_LIVE) ", %al			\n\
  ret							\n\
  .cfi_endproc						\n\
  .size set_context, .-set_context			\n\
  .previous						\n"
);

/* static */ char set_context (struct eri_context *ctx);

char __attribute__ ((noinline))
init_context (eri_file_t init, unsigned long start, unsigned long end)
{
  asm ("");
  struct eri_context ctx;
  eri_save_mark (init, ERI_MARK_INIT_STACK);
  eri_save_init_map_data (init, (const char *) start, end - start);
  char mode = set_context (&ctx);
  if (mode == ERS_LIVE)
    {
      eri_save_init_context (init, &ctx);
      eri_assert (eri_fclose (init) == 0);
    }
  else
    {
      eri_assert (eri_fprintf (ERI_STDERR, "replay!!!\n") == 0);
      eri_dump_maps (ERI_STDERR);
      ERI_ASSERT_SYSCALL (munmap, ctx.unmap_start, ctx.unmap_size);
    }
  return mode;
}

struct proc_map_data
{
  eri_file_t init;
  unsigned long pool_start;
  unsigned long replay_pool_start;
  unsigned long analysis_buf_start;

  /* The stack currently on, save it at last point.  */
  unsigned long stack_start, stack_end;
};

static void
proc_map_entry (const struct eri_map_entry *ent, void *data)
{
  if (ent->path
      && (eri_strcmp (ent->path, "[vvar]") == 0
	  || eri_strcmp (ent->path, "[vsyscall]") == 0))
    return;

  unsigned long start = ent->start;
  unsigned long end = ent->end;
  char perms = ent->perms;
  eri_assert (eri_fprintf (ERI_STDERR, "%lx-%lx %x\n", start, end, perms) == 0);

  if (perms & 8)
    eri_assert (eri_fprintf (ERI_STDERR, "warning: non private map\n") == 0);

  char flags = perms & 23;
  struct proc_map_data *d = data;
  if (start == d->pool_start
      || start == d->replay_pool_start
      || start == d->analysis_buf_start)
    flags |= 8;

  if (start <= (unsigned long) &start && end > (unsigned long) &start)
    {
      d->stack_start = start;
      d->stack_end = end;
      flags |= 16;
    }

  eri_save_mark (d->init, ERI_MARK_INIT_MAP);
  eri_save_init_map (d->init, start, end, flags);
  if (flags & 1 && ! (flags & 24)) /* readable & ! all zero */
    eri_save_init_map_data (d->init, (const char *) start, end - start);
}

static void ent_sigaction (int sig, struct eri_siginfo *info, void *ucontext);

static void __attribute__ ((used))
run_daemon (struct internal *internal)
{
  eri_loop_loop (internal->daemon.loop);

  eri_assert (eri_fprintf (ERI_STDERR, "exit daemon\n") == 0);
  ERI_ASSERT_SYSCALL (exit, 0);
}

#define NR_CLONE	_ERS_STR (__NR_clone)

#define DAEMON_FLAGS \
  (ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SIGHAND	\
   | ERI_CLONE_THREAD | ERI_CLONE_SYSVSEM | ERI_CLONE_SETTLS		\
   | ERI_CLONE_CHILD_CLEARTID)

asm ("  .text					\n\
  .align 16					\n\
  .type clone_daemon, @function			\n\
clone_daemon:					\n\
  .cfi_startproc				\n\
  .cfi_endproc					\n\
  subq	$8, %rdi				\n\
  movq	%rsi, (%rdi)				\n\
  movl	$" NR_CLONE ", %eax			\n\
  movq	%rdi, %rsi				\n\
  movq	$" _ERS_STR (DAEMON_FLAGS) ", %rdi	\n\
  movq	%rdx, %r10				\n\
  xorq	%r8, %r8				\n\
  syscall					\n\
  testq	%rax, %rax				\n\
  jl	.error					\n\
  jz	.daemon					\n\
  ret						\n\
.daemon:					\n\
  .cfi_startproc				\n\
  .cfi_undefined %rip				\n\
  xorq	%rbp, %rbp				\n\
  popq	%rdi					\n\
  call	run_daemon				\n\
  .cfi_endproc					\n\
.error:						\n\
  movq	$0, %r15				\n\
  movq	$0, (%r15)				\n\
  .size clone_daemon, .-clone_daemon		\n\
  .previous					\n"
);

/* static */ void clone_daemon (void *stack, struct internal *internal, void *ctid);

static void
start_daemon (struct internal *internal)
{
  size_t buf_size = 4 * 1024 * 1024;
  eri_assert (eri_malloc (&internal->pool, buf_size, &internal->daemon.p) == 0);

  size_t stack_size = 2 * 1024 * 1024;
  struct eri_mtpool *p = internal->daemon.p;
  size_t psize = eri_size_of (*p, 16);
  eri_assert (buf_size >= psize + stack_size);

  p->lock = 0;
  char *stack = (char *) p + psize;
  eri_assert (eri_init_pool (&p->pool, stack + stack_size,
			     buf_size - psize - stack_size) == 0);

  internal->daemon.loop = eri_loop_create (p);
  internal->daemon.ctid = 1;

  clone_daemon (stack + stack_size, internal, &internal->daemon.ctid);
}

#define SIGEXIT ERI_SIGURG

static char
init_process (struct internal *internal, const char *path)
{
#ifdef DEBUG
  internal->printf = 1;
#endif

  eri_assert (eri_fprintf (ERI_STDERR, "init_process %lx\n", internal) == 0);

  internal->path = path;
  if (ERI_SYSCALL_ERROR_P (ERI_SYSCALL (mkdir, path, ERI_S_IRWXU)))
    eri_assert (eri_fprintf (ERI_STDERR, "failed to create %s\n", path) == 0);

#ifdef DEBUG
  size_t file_buf_size = internal->file_buf_size = 0;
#else
  size_t file_buf_size = internal->file_buf_size = 64 * 1024;
#endif
  struct lock *locks[] = INTERNAL_LOCKS (internal);
  size_t nlocks = eri_length_of (locks);
  size_t pool_size = 64 * 1024 * 1024;
  eri_assert (pool_size >= (nlocks + ERI_NSIG) * file_buf_size);
  internal->pool_buf = (char *) ERI_ASSERT_SYSCALL_RES (
		mmap, 0, pool_size, ERI_PROT_READ | ERI_PROT_WRITE,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  internal->pool_buf_size = pool_size - (nlocks + ERI_NSIG) * file_buf_size;
  internal->ilock_file_buf = internal->pool_buf + internal->pool_buf_size;

  size_t replay_pool_size = 32 * 1024 * 1024;
  internal->replay.pool_buf = (char *) ERI_ASSERT_SYSCALL_RES (
		mmap, 0, replay_pool_size, ERI_PROT_READ | ERI_PROT_WRITE,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  internal->replay.pool_buf_size = replay_pool_size;

  size_t analysis_buf_size = 512 * 1024 * 1024;
  internal->analysis.buf = (char *) ERI_ASSERT_SYSCALL_RES (
		mmap, 0, analysis_buf_size, ERI_PROT_READ | ERI_PROT_WRITE,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  internal->analysis.buf_size = analysis_buf_size;

  eri_assert (eri_fprintf (ERI_STDERR, "pool_buf %lx\n", internal->pool_buf) == 0);
  eri_dump_maps (ERI_STDERR);

  eri_file_buf_t init_buf[32 * 1024];
  eri_file_t init = eri_open_path (path, "init", 0, 0, init_buf, sizeof init_buf);
  struct proc_map_data pd = { init, (unsigned long) internal->pool_buf,
			      (unsigned long) internal->replay.pool_buf,
			      (unsigned long) internal->analysis.buf };
  eri_process_maps (proc_map_entry, &pd);

  eri_assert (pd.stack_start);
  char mode = internal->mode = init_context (init, pd.stack_start,
					     pd.stack_end);

  eri_assert (eri_init_pool (&internal->pool,
			     internal->pool_buf,
			     internal->pool_buf_size) == 0);

  start_daemon (internal);

  if (mode != ERS_LIVE)
    eri_assert (eri_init_pool (&internal->replay.pool.pool,
			       internal->replay.pool_buf,
			       internal->replay.pool_buf_size) == 0);

  ERI_LST_INIT_LIST (thread, internal);

  int i;
  for (i = 0; i < nlocks; ++i)
    {
      eri_file_t lfile = eri_open_path (path, "lock-",
	ERI_OPEN_WITHID | (mode != ERS_LIVE) * ERI_OPEN_READ, i,
	internal->ilock_file_buf + i * file_buf_size, file_buf_size);

      init_lock (internal, locks[i], lfile);
    }

  struct thread *th = internal->main = alloc_thread (internal, 0, 0, 0);
  /* if (mode != ERS_LIVE) th->id = 0; */
  start_thread (internal, th);

  internal->sys_pid = SYSCALL_REC_RES (mode, th->file, __NR_getpid);
  eri_assert (! ERI_SYSCALL_ERROR_P (internal->sys_pid));

  for (i = 1; i < ERI_NSIG; ++i)
    if (i != ERI_SIGKILL && i != ERI_SIGSTOP)
      {
	eri_file_t lfile = eri_open_path (path, "sigact-",
	  ERI_OPEN_WITHID  | (mode != ERS_LIVE) * ERI_OPEN_READ, i,
	  internal->ilock_file_buf + (nlocks + i) * file_buf_size, file_buf_size);

	init_lock (internal, &internal->sigacts[i].lock, lfile);
      }

  struct eri_sigaction a = { ent_sigaction, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn };
  eri_assert (! ERI_SYSCALL_ERROR_P (
    SYSCALL_REC_RES (mode, th->file, __NR_rt_sigaction, SIGEXIT, &a, 0, ERI_SIG_SETSIZE)));

  release_thread (internal, (unsigned long) th, ACQUIRE_INIT);
  return mode;
}

static struct thread *
get_thread (struct internal *internal)
{
  if (internal->main) return internal->main;
  struct thread *th;
  asm ("movq	%%fs:(%1), %0" : "=r" (th) : "r" (internal->thread_offset));
  return th;
}

static void
set_thread (struct internal *internal, struct thread *th)
{
  asm ("movq	%0, %%fs:(%1)" : : "r" (th), "r" (internal->thread_offset));
}

static void
setup_tls (struct internal *internal, long offset)
{
  eri_assert (internal->main);

  /* Call set_thread first to avoid possible gap in analysis.  */
  internal->thread_offset = offset;
  set_thread (internal, internal->main);
  internal->main = 0;

  if (internal->mode == ERS_LIVE)
    {
      eri_file_buf_t dmp_buf[32 * 1024];
      eri_file_t dmp = eri_open_path (internal->path, "maps-log", 0, 0,
		     		      dmp_buf, sizeof dmp_buf);
      eri_dump_maps (dmp);
      eri_assert (eri_fclose (dmp) == 0);
    }
}

static void
save_result_out (eri_file_t file, long res, const void *out, size_t size)
{
  save_result (file, res);
  if (! ERI_SYSCALL_ERROR_P (res) && out && size)
    eri_assert (eri_fwrite (file, out, size, 0) == 0);
}

static long
load_result_out (eri_file_t file, void *out, size_t size)
{
  long res = load_result (file);
  if (size == -1) size = res;
  if (! ERI_SYSCALL_ERROR_P (res) && out && size)
    eri_assert (eri_fread (file, out, size, 0) == 0);
  return res;
}

#define SYSCALL_REC_RES_OUT(mode, file, out, nr, ...) \
  ({									\
    long __res;								\
    if (mode == ERS_LIVE)						\
      {									\
	__res = ERI_SYSCALL_NCS (nr, __VA_ARGS__);			\
	save_result_out (file, __res, out, sizeof *out);		\
      }									\
    else __res = load_result_out (file, out, sizeof *out);		\
    __res;								\
  })

static void
ent_sigaction (int sig, struct eri_siginfo *info, void *ucontext);

static struct atomic_lock *
get_atomic_lock (struct internal *internal, struct thread * th,
		 void *mem, char create)
{
  ilock (internal, th->id, &internal->atomics_lock);
  struct atomic_lock *lock = atomic_rbt_get (internal, &mem, ERI_RBT_EQ);
  if (create && ! lock)
    {
      size_t lock_size = eri_size_of (*lock, 16);
      size_t buf_size = internal->file_buf_size;
      lock = icalloc (internal, th->id, lock_size + buf_size, sizeof *lock);
      lock->mem = mem;
#ifndef NO_CHECK
      iprintf (internal, th->log, "get_atomic_lock %lu %lu\n", th->id, mem);
#endif

      eri_file_t lfile = eri_open_path (internal->path, "atomic-",
	ERI_OPEN_WITHID | (internal->mode != ERS_LIVE) * ERI_OPEN_READ,
	(unsigned long) mem, (char *) lock + lock_size, buf_size);
      init_lock (internal, &lock->lock, lfile);
      atomic_rbt_insert (internal, lock);
    }
  iunlock (internal, &internal->atomics_lock, 0);
  return lock;
}

struct rlimit { char buf[16]; };
struct stat { char buf[144]; };

static void
do_exit_group (struct internal *internal)
{
  struct thread *t, *nt;
  ERI_LST_FOREACH_SAFE (thread, internal, t, nt) fini_thread (internal, t);

  struct lock *locks[] = INTERNAL_LOCKS (internal);
  int i;
  for (i = 0; i < eri_length_of (locks); ++i)
    {
      eri_assert (locks[i]->lock == 0);
      eri_assert (eri_fclose (locks[i]->file) == 0);
    }

  if (internal->mode != ERS_LIVE) replay_exit (&internal->replay);
  ERI_ASSERT_SYSCALL (munmap, internal->replay.pool_buf,
		      internal->replay.pool_buf_size);

  eri_loop_exit (internal->daemon.loop, 0);
  eri_lock (&internal->daemon.ctid);

  eri_assert (eri_fini_pool (&((struct eri_mtpool *) internal->daemon.p)->pool) == 0);
  eri_assert (eri_free (&internal->pool, internal->daemon.p) == 0);

  eri_assert (eri_fprintf (ERI_STDERR, "used %lu\n", internal->pool.used) == 0);
  eri_assert (eri_fini_pool (&internal->pool) == 0);
  ERI_ASSERT_SYSCALL (munmap, internal->pool_buf, internal->pool_buf_size);
}

static void
do_exit (struct internal *internal, struct thread *th)
{
  fini_thread (internal, th);
  release_thread (internal, th->id, ACQUIRE_EXIT);
}

static void
sysexit (struct internal *internal, int nr, long status)
{
  struct thread *th = get_thread (internal);
  acquire_thread (internal, th, ACQUIRE_EXIT);

  eri_assert (nr == __NR_exit || nr == __NR_exit_group);

  unsigned long tid = th->id;
  iprintf (internal, th->log, "sysexit %lu %u\n", tid, nr);

  check_syscall (internal, th->file, nr);

  char mode = internal->mode;
  char grp = tid == 0 /* main thread */
	     || nr == __NR_exit_group;
  if (grp)
    {
      release_thread (internal, tid, ACQUIRE_EXIT);
      while (! ATOMIC_COMPARE_EXCHANGE (internal, tid, &internal->active_lock, 0,
					LONG_MIN))
	ERI_ASSERT_SYSCALL (sched_yield);

      ATOMIC_STORE (internal, tid, &internal->exit, 1);

      struct thread *t;
      ERI_LST_FOREACH (thread, internal, t)
	if (t != th)
	  eri_assert (! ERI_SYSCALL_ERROR_P (
	    SYSCALL_REC_RES (mode, th->file, __NR_tgkill,
			     internal->sys_pid, t->sys_tid, SIGEXIT)));
      ERI_LST_FOREACH (thread, internal, t)
	if (t != th)
	  while (! ATOMIC_LOAD (internal, tid, &t->exit))
	    ERI_ASSERT_SYSCALL (sched_yield);

      iprintf (internal, th->log, "group exiting\n");

      int i;
      for (i = 1; i < ERI_NSIG; ++i)
	if (i != ERI_SIGKILL && i != ERI_SIGSTOP)
	  {
	    struct sigact_wrap *w = internal->sigacts + i;
	    if (mode == ERS_LIVE) eri_assert (w->lock.lock == 0);
	    else eri_assert (w->lock.tid == -1);
	    eri_assert (eri_fclose (w->lock.file) == 0);
	  }

      struct atomic_lock *l, *nl;
      ERI_RBT_FOREACH_SAFE (atomic, internal, l, nl)
	{
	  iprintf (internal, 0, "remove atomic lock %lx\n", l);

	  /* Possibly locked because of thread still existing.  */
	  if (mode == ERS_LIVE)
	    while (__atomic_load_n (&l->lock.lock, __ATOMIC_ACQUIRE)) continue;
	  else eri_assert (l->lock.tid == -1);

	  eri_assert (eri_fclose (l->lock.file) == 0);
	  atomic_rbt_remove (internal, l);
	  ifree (internal, tid, l);
	}

      if (mode != ERS_ANALYSIS)
	{
	  ERI_ASSERT_SYSCALL (munmap, internal->analysis.buf,
			      internal->analysis.buf_size);
	  do_exit_group (internal);
	}
    }
  else
    {
      if (th->clear_tid)
	{
	  iprintf (internal, th->log, "clear_tid %lx\n", th->clear_tid);
	  struct lock *lock = &get_atomic_lock (internal, th, th->clear_tid, 1)->lock;
	  llock (internal, tid, lock);
	  *th->clear_tid = 0;

	  ERI_ASSERT_SYSCALL (futex, th->clear_tid, ERI_FUTEX_WAKE, 1);

	  /* So it's locked until real clear_tid happens.  */
	  ERI_ASSERT_SYSCALL (set_tid_address, &lock->lock);
	  lunlock (internal, lock, 1);
	}

      if (mode != ERS_ANALYSIS) do_exit (internal, th);
    }
  ERI_SYSCALL_NCS (nr, mode == ERS_LIVE ? status : 0);
  eri_assert (0);
}

static long
syscomm (struct internal *internal, int nr,
	 long a1, long a2, long a3, long a4, long a5, long a6)
{
  eri_assert (nr != __NR_clone);
  eri_assert (nr != __NR_exit && nr != __NR_exit_group);

  struct thread *th = get_thread (internal);
  acquire_thread (internal, th, ACQUIRE_NORMAL);

  unsigned long tid = th->id;
  iprintf (internal, th->log, "syscall %lu %u\n", tid, nr);

  check_syscall (internal, th->file, nr);

  char mode = internal->mode;
  long res;
  if (nr == __NR_rt_sigaction)
    {

      if (a1 <= 0 || a1 >= ERI_NSIG
	  || a1 == ERI_SIGKILL || a1 == ERI_SIGSTOP
	  || (a2 == 0 && a3 == 0))
	res = SYSCALL_REC_RES (mode, th->file, nr, a1, a2, a3, a4);
      else
	{
	  struct sigact_wrap *w = internal->sigacts + a1;

	  llock (internal, tid, &w->lock);
	  void *oact = w->act;
	  int oflags = w->flags;

	  struct eri_sigaction *act = (struct eri_sigaction *) a2;
	  if (act)
	    {
	      w->act = act->act;
	      w->flags = act->flags;
	    }

	  if (act
	      && ((act->act != ERI_SIG_DFL && act->act != ERI_SIG_IGN) || a1 == SIGEXIT))
	    {
	      struct eri_sigaction a = {
		ent_sigaction, act->flags | ERI_SA_SIGINFO, act->restorer, act->mask
	      };
	      res = SYSCALL_REC_RES (mode, th->file, nr, a1, &a, a3, a4);
	    }
	  else
	    res = SYSCALL_REC_RES (mode, th->file, nr, a1, act, a3, a4);

	  struct eri_sigaction *old = (struct eri_sigaction *) a3;
	  if (old)
	    {
	      old->act = oact;
	      old->flags = oflags;
	    }

	  lunlock (internal, &w->lock, 0);
	}
    }
  else if (nr == __NR_set_tid_address)
    {
      th->clear_tid = (int *) a1;
      res = SYSCALL_REC_RES (mode, th->file, nr, a1);
    }
  else if (nr == __NR_set_robust_list)
    res = SYSCALL_REC_RES (mode, th->file, nr, a1, a2);
  else if (nr == __NR_rt_sigprocmask)
    res = SYSCALL_REC_RES_OUT (mode, th->file, (struct eri_sigset *) a3,
			       nr, a1, a2, a3);
  else if (nr == __NR_prlimit64)
    res = SYSCALL_REC_RES_OUT (mode, th->file, (struct rlimit *) a4,
			       nr, a1, a2, a3, a4);
  else if (nr == __NR_clock_gettime)
    res = SYSCALL_REC_RES_OUT (mode, th->file, (struct eri_timespec *) a2,
			       nr, a1, a2);
  else if (nr == __NR_read)
    {
      release_thread (internal, (unsigned long) th, ACQUIRE_NORMAL);

      if (mode == ERS_LIVE)
	res = ERI_SYSCALL_NCS (nr, a1, a2, a3);

      acquire_thread (internal, th, ACQUIRE_NORMAL);
      if (mode == ERS_LIVE)
	save_result_out (th->file, res, (void *) a2, res);
      else res = load_result_out (th->file, (void *) a2, -1);
    }
  else if (nr == __NR_write)
    res = SYSCALL_REC_IRES (internal, th, nr, a1, a2, a3);
  else if (nr == __NR_stat)
    res = SYSCALL_REC_RES_OUT (mode, th->file, (struct stat *) a2,
			       nr, a1, a2);
  else if (nr == __NR_fstat)
    res = SYSCALL_REC_RES_OUT (mode, th->file, (struct stat *) a2,
			       nr, a1, a2);
  else if (nr == __NR_openat)
    res = SYSCALL_REC_RES (mode, th->file, nr, a1, a2, a3, a4);
  else if (nr == __NR_close)
    res = SYSCALL_REC_IRES (internal, th, nr, a1);
  else if (nr == __NR_writev)
    res = SYSCALL_REC_IRES (internal, th, nr, a1, a2, a3);
  else if (nr == __NR_access)
    res = SYSCALL_REC_RES (mode, th->file, nr, a1, a2);
  else if (nr == __NR_mmap)
    {
      char anony = a4 & ERI_MAP_ANONYMOUS;
      llock (internal, tid, &internal->mmap_lock);
      if (mode == ERS_LIVE)
	{
	  res = ERI_SYSCALL_NCS (nr, a1, a2, a3, a4, a5, a6);
	  save_result_out (th->file, res, (void *) res, anony ? 0 : (size_t) a2);
	}
      else
	{
	  res = load_result (th->file);
	  if (! ERI_SYSCALL_ERROR_P (res))
	    {
	      ERI_ASSERT_SYSCALL (mmap, res, a2, anony ? a3 : a3 | ERI_PROT_WRITE,
				  ERI_MAP_FIXED | ERI_MAP_ANONYMOUS | ERI_MAP_PRIVATE,
				  -1, 0);

	      if (! anony)
		{
		  eri_assert (eri_fread (th->file, (void *) res, (size_t) a2, 0) == 0);
		  if ((a3 & ERI_PROT_WRITE) == 0)
		    ERI_ASSERT_SYSCALL (mprotect, res, a2, a3);
		}
	    }
	}
      lunlock (internal, &internal->mmap_lock, 0);
    }
  else if (nr == __NR_mprotect)
    res = SYSCALL_CHECK_RES (mode, th->file, nr, a1, a2, a3);
  else if (nr == __NR_brk)
    {
      llock (internal, tid, &internal->brk_lock);

      if (! internal->cur_brk && a1)
	internal->cur_brk = SYSCALL_REC_RES (mode, th->file, nr, 0);

      res = SYSCALL_REC_RES (mode, th->file, nr, a1);
      eri_assert (! ERI_SYSCALL_ERROR_P (res));

      if (a1 == 0)
	{
	  if (! internal->cur_brk) internal->cur_brk = (unsigned long) res;
	  else eri_assert (internal->cur_brk == (unsigned long) res);
	}
      else if (res == a1)
	{
	  if (mode != ERS_LIVE)
	    {
	      unsigned long c = eri_round_up (internal->cur_brk, 4096);
	      unsigned long n = eri_round_up ((unsigned long) res, 4096);
	      if (n > c)
		ERI_ASSERT_SYSCALL (mmap, c, n - c,
				    ERI_PROT_READ | ERI_PROT_WRITE | ERI_PROT_EXEC,
				    ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS | ERI_MAP_FIXED,
				    -1, 0);
	      else if (c > n)
		ERI_ASSERT_SYSCALL (munmap, n, c - n);
	    }
	  internal->cur_brk = (unsigned long) res;
	}

      eri_assert (internal->cur_brk);
      lunlock (internal, &internal->brk_lock, 0);
    }
  else if (nr == __NR_munmap)
    {
      llock (internal, tid, &internal->mmap_lock);
      res = SYSCALL_CHECK_RES (mode, th->file, nr, a1, a2);
      lunlock (internal, &internal->mmap_lock, 0);
    }
  else if (nr == __NR_futex)
    {
      int op = a2 & ERI_FUTEX_CMD_MASK;
      eri_assert (op != ERI_FUTEX_WAKE_OP); /* XXX */
      if (op == ERI_FUTEX_WAIT || op == ERI_FUTEX_WAIT_BITSET)
	release_thread (internal, (unsigned long) th, ACQUIRE_NORMAL);

      if (mode == ERS_LIVE)
	res = ERI_SYSCALL_NCS (nr, a1, a2, a3, a4, a5, a6);

      if (op == ERI_FUTEX_WAIT || op == ERI_FUTEX_WAIT_BITSET)
	acquire_thread (internal, th, ACQUIRE_NORMAL);

      if (mode == ERS_LIVE) save_result (th->file, res);
      else res = load_result (th->file);
    }
  else if (nr == __NR_getpid)
    res = SYSCALL_REC_RES (mode, th->file, nr);
  else if (nr == __NR_gettid)
    res = SYSCALL_REC_RES (mode, th->file, nr);
  else if (nr == __NR_madvise)
    /* XXX check advice */
    res = SYSCALL_REC_RES (mode, th->file, nr, a1, a2, a3);
  else if (nr == __NR_time)
    res = SYSCALL_REC_RES_OUT (mode, th->file, (long *) a1, nr, a1);
  else if (nr == __NR_arch_prctl)
    {
      if (a1 != ERI_ARCH_GET_FS && a1 != ERI_ARCH_GET_GS)
	res = SYSCALL_REC_RES (mode, th->file, nr, a1, a2);
      else
	res = SYSCALL_REC_RES_OUT (mode, th->file,
				   (unsigned long *) a2, nr, a1, a2);
    }
  else
    {
      iprintf (internal, th->log, "not support %u\n", nr);
      eri_assert (0);
    }

  iprintf (internal, th->log, "syscall done %lu %u\n", tid, nr);
  release_thread (internal, (unsigned long) th, ACQUIRE_NORMAL);
  return res;
}

static long __attribute__ ((used))
syscall (struct internal *internal, int nr,
	 long a1, long a2, long a3, long a4, long a5, long a6)
{
  eri_assert (nr != __NR_clone);
  if (nr == __NR_exit || nr == __NR_exit_group)
    {
      sysexit (internal, nr, a1);
      eri_assert (0);
      __builtin_unreachable ();
    }

  return syscomm (internal, nr, a1, a2, a3, a4, a5, a6);
}

#define CLONE_FLAGS \
  (ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SIGHAND	\
   | ERI_CLONE_THREAD | ERI_CLONE_SYSVSEM | ERI_CLONE_SETTLS		\
   | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID)

static char __attribute__ ((used))
pre_clone (struct internal *internal, struct eri_clone_desc *desc)
{
  struct thread *th = get_thread (internal);
  acquire_thread (internal, th, ACQUIRE_CLONE, 2);

  eri_assert (internal->main == 0);
  eri_assert (desc->flags == CLONE_FLAGS);

  iprintf (internal, th->log, "pre_clone %lu\n", th->id);

  check_syscall (internal, th->file, __NR_clone);

  char mode = internal->mode;
  struct thread *c = alloc_thread (internal, th->id, desc->ctid, desc->tp);
  *(struct thread **) ((char *) desc->tp + internal->thread_offset) = c;
  desc->child = c;
  eri_memcpy (&c->old_set, &th->old_set, sizeof th->old_set);

  if (mode == ERS_LIVE)
    save_result (th->file, c->id);
  else
    {
      c->id = (unsigned long) load_result (th->file);

      desc->replay_result = load_result (th->file);
      eri_assert (desc->replay_result);

      c->sys_tid = desc->replay_result;

      if (ERI_SYSCALL_ERROR_P (desc->replay_result))
	{
	  iprintf (internal, th->log, "pre_clone done %lu\n", th->id);
	  return 0;
	}

      if (mode == ERS_ANALYSIS)
	analysis_break (ANALYSIS_CLONE, c);

      desc->flags &= ~(ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID);
      *desc->ptid = desc->replay_result;
    }
  iprintf (internal, th->log, "pre_clone done %lu\n", th->id);
#ifndef NO_CHECK
  llock (internal, th->id, &internal->clone_lock);
#endif
  return 1;
}

static long __attribute__ ((used))
post_clone (struct internal *internal, struct thread *child, long res, long replay)
{
  struct thread *th = get_thread (internal);
  char mode = internal->mode;

  if (mode == ERS_LIVE)
    {
      if (res != 0)
	save_result (th->file, res);
    }
  else
    {
      if (ERI_SYSCALL_ERROR_P (replay)) /* clone shall fail, no syscall */
	res = replay;
      else if (ERI_SYSCALL_ERROR_P (res)) /* clone should not fail */
	{
	  eri_assert (eri_fprintf (ERI_STDERR, "failed to clone thread\n") == 0);
	  eri_assert (0);
	}
      else if (res != 0) /* clone succeeded and we are the parent, replace the result */
	res = replay;
    }

  long rel = 1;
  if (res != 0)
    {
#ifndef NO_CHECK
      /* the parent release the lock */
      lunlock (internal, &internal->clone_lock, 0);
#endif

      iprintf (internal, th->log, "post_clone %lu %lu\n", th->id, res);

      if (ERI_SYSCALL_ERROR_P (res))
	{
	  ifree (internal, th->id, child);
	  rel = 2;
	}
    }
  else
    {
      eri_assert (th == child);
      start_thread (internal, th);
      iprintf (internal, th->log, "post_clone %lu %lu\n", th->id, res);
    }

  iprintf (internal, th->log, "post_clone done %lu\n", th->id);
  release_thread (internal, (unsigned long) th, ACQUIRE_CLONE, rel);
  return res;
}

static void
sigaction (struct internal *internal, int sig,
	   struct eri_siginfo *info, void *ucontext)
{
  void *act;
  int flags;

  struct thread *th = get_thread (internal);
  acquire_thread (internal, th, ACQUIRE_ASYNC);

  unsigned long tid = th->id;
  iprintf (internal, th->log, "sigaction %lu %u\n", tid, sig);

  if (internal->mode == ERS_LIVE)
    save_signal (th->file, sig, info, ucontext);

  if (sig == SIGEXIT && ATOMIC_LOAD (internal, tid, &internal->exit))
    {
      ATOMIC_STORE (internal, tid, &th->exit, 1);
      while (1) continue;
    }

  struct sigact_wrap *w = internal->sigacts + sig;
  llock (internal, tid, &w->lock);

  eri_assert (sig == SIGEXIT
	      || (w->act != ERI_SIG_DFL && w->act != ERI_SIG_IGN));
  act = w->act;
  flags = w->flags;

  lunlock (internal, &w->lock, 0);

  iprintf (internal, th->log, "sigaction done %lu %u\n", tid, sig);
  release_thread (internal, (unsigned long) th, ACQUIRE_ASYNC);

  if (act == ERI_SIG_DFL || act == ERI_SIG_IGN) return;

  if (flags & ERI_SA_SIGINFO)
    ((void (*) (int, struct eri_siginfo *, void *)) act) (sig, info, ucontext);
  else
    ((void (*) (int)) act) (sig);
}

static void
atomic_lock (struct internal *internal, void *mem)
{
  struct thread *th = get_thread (internal);
  acquire_thread (internal, th, ACQUIRE_NORMAL);

  iprintf (internal, th->log, "atomic_lock %lu %lx\n", th->id, mem);

  struct atomic_lock *lock = get_atomic_lock (internal, th, mem, 1);
  llock (internal, th->id, &lock->lock);
  iprintf (internal, th->log, "atomic_lock done %lu %lx\n", th->id, mem);

  analysis_leave_silence (internal);
}

static void
atomic_unlock (struct internal *internal, void *mem, int mo)
{
  analysis_enter_silence (internal);

  struct thread *th = get_thread (internal);
  iprintf (internal, th->log, "atomic_unlock %lu %lx %u\n", th->id, mem, mo);

  struct atomic_lock *lock = get_atomic_lock (internal, th, mem, 0);
  eri_assert (lock);
  lunlock (internal, &lock->lock, 0);
  iprintf (internal, th->log, "atomic_unlock done %lu %lx %u\n", th->id, mem, mo);

  release_thread (internal, (unsigned long) th, ACQUIRE_NORMAL);
}

static void
atomic_barrier (struct internal *internal, int mo)
{
#if 0
  if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE)) return 0;
  struct ers_thread *th = get_thread (internal);
  iprintf (internal, th->log, "atomic_barrier %lu %u\n", th->id, mo);

  release_active_lock (internal, th->id, 1, 0);
  return 1;
#endif
}

static void
analysis_proc_break (struct eri_vex_brk_desc *desc)
{
  eri_assert (desc->ctx->rip != 0);
  eri_assert (! (desc->type & ERI_VEX_BRK_PRE_EXEC));

  struct internal *internal = desc->data;
  /* Ensure internal->main = 0 atomic.  */
  struct thread *th = internal->main
    ? : *(struct thread **) (desc->ctx->fsbase + internal->thread_offset);

  struct analysis *al = &internal->analysis;
  if (! al->analysis)
    {
      al->analysis = eri_analysis_create (al->pool, &internal->printf_lock);
      th->analysis = eri_analysis_create_thread (al->analysis, NULL, th->id);
    }

  eri_analysis_record (th->analysis, desc);

  if (desc->ctx->rip == (unsigned long) analysis_break)
    {
      unsigned long type = desc->ctx->rdi;
      if (type == ANALYSIS_ERROR)
	__atomic_store_n (&al->error, 1, __ATOMIC_RELEASE);
      else if (type == ANALYSIS_CLONE)
	{
	  struct thread *child = (struct thread *) desc->ctx->rsi;
	  child->analysis = eri_analysis_create_thread (al->analysis, th->analysis, child->id);
	}
      else if (type == ANALYSIS_ENTER_SILENCE || type == ANALYSIS_LEAVE_SILENCE)
	eri_analysis_silence (th->analysis, type == ANALYSIS_ENTER_SILENCE);
      else if (type == ANALYSIS_LLOCK)
	eri_analysis_sync_acq (th->analysis, desc->ctx->rsi, desc->ctx->rdx);
      else if (type == ANALYSIS_LUNLOCK)
	eri_analysis_sync_rel (th->analysis, desc->ctx->rsi, desc->ctx->rdx, desc->ctx->rcx);
      else eri_assert (type == ANALYSIS_NONE);
    }

  if (! (desc->type & ERI_VEX_BRK_EXIT_MASK)) return;

  eri_assert_lprintf (&internal->printf_lock, "analysis exit %lu %u %lu\n",
		      th->id, desc->type, desc->ctx->rdi & ERI_VEX_BRK_EXIT_MASK);

  eri_analysis_delete_thread (th->analysis);

  if (desc->type & ERI_VEX_BRK_EXIT_GROUP)
    eri_analysis_delete (al->analysis);

  if (__atomic_load_n (&internal->analysis.error, __ATOMIC_ACQUIRE)) return;

  /* Group exit is already synced by us.  */
  eri_assert (! (desc->type & ERI_VEX_BRK_EXIT_WAIT));
  if (desc->type & ERI_VEX_BRK_EXIT_GROUP)
    do_exit_group (internal);
  else if (desc->type & ERI_VEX_BRK_EXIT)
    do_exit (internal, th);
}

asm ("  .text					\n\
  .align 16					\n\
  .type analysis_entry, @function		\n\
analysis_entry:					\n\
  movq	%rdi, %r12				\n\
  movq	%rsi, %r13				\n\
  movq	$" _ERS_STR (ANALYSIS_NONE) ", %rdi	\n\
  call	analysis_break				\n\
  movq	%r13, %rsi				\n\
  jmp	*%r12					\n\
  .size analysis_entry, .-analysis_entry	\n\
  .previous					\n"
);

/* static */ void analysis_entry (unsigned long entry, unsigned long arg);

static void
analysis (struct internal *internal,
	  unsigned long entry, unsigned long arg, unsigned long stack)
{
  eri_assert (internal->mode == ERS_ANALYSIS);

  struct eri_vex_desc desc = {
    internal->analysis.buf, internal->analysis.buf_size, 1,
    4096, internal->path, &internal->printf_lock,
    analysis_proc_break, ~ERI_VEX_BRK_PRE_EXEC, internal
  };
  /* Ensure analysis initialized before any new threads created.  */
  desc.comm.rip = (unsigned long) analysis_entry;
  desc.comm.rdi = entry;
  desc.comm.rsi = arg;
  desc.comm.rsp = stack;

  desc.pool = &internal->analysis.pool;

  eri_vex_enter (&desc);
  eri_assert (0);
}

static struct internal internal;

static char
ent_init_process (const char *path)
{
  return init_process (&internal, path);
}

static void
ent_setup_tls (long offset)
{
  setup_tls (&internal, offset);
}

/* static */ long ent_syscall (int nr, long a1, long a2, long a3, long a4,
			       long a5, long a6);

#define CLONE_DESC_SIZE16		_ERS_STR (ERI_CLONE_DESC_SIZE16)

#define CLONE_DESC_CHILD		_ERS_STR (ERI_CLONE_DESC_CHILD)
#define CLONE_DESC_FLAGS		_ERS_STR (ERI_CLONE_DESC_FLAGS)
#define CLONE_DESC_CSTACK		_ERS_STR (ERI_CLONE_DESC_CSTACK)
#define CLONE_DESC_PTID			_ERS_STR (ERI_CLONE_DESC_PTID)
#define CLONE_DESC_CTID			_ERS_STR (ERI_CLONE_DESC_CTID)
#define CLONE_DESC_TP			_ERS_STR (ERI_CLONE_DESC_TP)
#define CLONE_DESC_REPLAY_RESULT	_ERS_STR (ERI_CLONE_DESC_REPLAY_RESULT)

asm ("  .text							\n\
  .align 16							\n\
  .type ent_syscall, @function					\n\
ent_syscall:							\n\
  .cfi_startproc						\n\
								\n\
  cmpl	$" NR_CLONE ", %edi					\n\
  je	.call_clone						\n\
								\n\
  subq	$8, %rsp		/* alignment */			\n\
  .cfi_adjust_cfa_offset 8					\n\
  pushq	16(%rsp)		/* a6 */			\n\
  .cfi_adjust_cfa_offset 8					\n\
  pushq	%r9			/* a5 */			\n\
  .cfi_adjust_cfa_offset 8					\n\
  movq	%r8, %r9		/* a4 */			\n\
  movq	%rcx, %r8		/* a3 */			\n\
  movq	%rdx, %rcx		/* a2 */			\n\
  movq	%rsi, %rdx		/* a1 */			\n\
  movl	%edi, %esi		/* nr */			\n\
  leaq	internal(%rip), %rdi	/* internal */			\n\
  call	syscall							\n\
  addq	$24,  %rsp						\n\
  .cfi_adjust_cfa_offset -24					\n\
  ret								\n\
								\n\
.call_clone:							\n\
  call .clone							\n\
  .cfi_endproc							\n\
								\n\
.clone:								\n\
  .cfi_startproc						\n\
  subq	$" CLONE_DESC_SIZE16 ", %rsp				\n\
  .cfi_adjust_cfa_offset " CLONE_DESC_SIZE16 "			\n\
  movq	%rsi, " CLONE_DESC_FLAGS "(%rsp)			\n\
  movq	%rdx, " CLONE_DESC_CSTACK "(%rsp)			\n\
  movq	%rcx, " CLONE_DESC_PTID "(%rsp)				\n\
  movq	%r8, " CLONE_DESC_CTID "(%rsp)				\n\
  movq	%r9, " CLONE_DESC_TP "(%rsp)				\n\
								\n\
  movq	%rsp, %rsi		/* desc */			\n\
  leaq	internal(%rip), %rdi	/* internal */			\n\
  call	pre_clone						\n\
  testb	 %al, %al 		/* replay & no syscall */	\n\
  jz	.post							\n\
								\n\
  movq	" CLONE_DESC_TP "(%rsp), %r8				\n\
  movq	" CLONE_DESC_CTID "(%rsp), %r10				\n\
  movq	" CLONE_DESC_PTID "(%rsp), %rdx				\n\
  movq	" CLONE_DESC_CSTACK "(%rsp), %rsi			\n\
  movq	" CLONE_DESC_FLAGS "(%rsp), %rdi			\n\
								\n\
  subq	$32, %rsi						\n\
  movq	" CLONE_DESC_SIZE16 " + 8(%rsp), %rax			\n\
  movq	%rax, 24(%rsi)		/* return address */		\n\
  movq	" CLONE_DESC_CHILD "(%rsp), %rax			\n\
  movq	%rax, (%rsi)		/* child */			\n\
  movq	" CLONE_DESC_REPLAY_RESULT "(%rsp), %rax		\n\
  movq	%rax, 8(%rsi)		/* replay */			\n\
								\n\
  movl	$" NR_CLONE ", %eax	/* nr_clone */			\n\
  syscall							\n\
  .cfi_undefined %rip						\n\
								\n\
  testq	%rax, %rax						\n\
  jz	.child							\n\
  .cfi_restore %rip						\n\
								\n\
.post:								\n\
  movq	%rax, %rdx		/* res */			\n\
  movq	" CLONE_DESC_REPLAY_RESULT "(%rsp), %rcx		\n\
  movq	" CLONE_DESC_CHILD "(%rsp), %rsi			\n\
  leaq	internal(%rip), %rdi	/* internal */			\n\
  call	post_clone						\n\
  addq	$" CLONE_DESC_SIZE16 " + 8, %rsp			\n\
  .cfi_adjust_cfa_offset -" CLONE_DESC_SIZE16 "			\n\
  .cfi_rel_offset %rip, 0					\n\
  ret								\n\
								\n\
.child:								\n\
  .cfi_undefined %rip						\n\
  movq	8(%rsp), %rcx		/* replay */			\n\
  movq	$0, %rdx		/* res */			\n\
  movq	(%rsp), %rsi		/* child */			\n\
  leaq	internal(%rip), %rdi	/* internal */			\n\
  call	post_clone						\n\
  addq	$24, %rsp						\n\
  xorq	%rax, %rax						\n\
  ret								\n\
  .cfi_endproc							\n\
  .size ent_syscall, .-ent_syscall				\n\
  .previous							\n"
);

static void
ent_atomic_lock (void *mem)
{
  return atomic_lock (&internal, mem);
}

static void
ent_atomic_unlock (void *mem, int mo)
{
  atomic_unlock (&internal, mem, mo);
}

static void
ent_atomic_barrier (int mo)
{
  return atomic_barrier (&internal, mo);
}

static void
ent_analysis (unsigned long entry, unsigned long arg,
	      unsigned long stack)
{
  analysis (&internal, entry, arg, stack);
}

static struct ers_recorder recorder = {

  ent_init_process,
  ent_setup_tls,
  ent_syscall,
  ent_atomic_lock,
  ent_atomic_unlock,
  ent_atomic_barrier,
  ent_analysis
};

struct ers_recorder *
eri_get_recorder (void)
{
  return &recorder;
}

static void
ent_sigaction (int sig, struct eri_siginfo *info, void *ucontext)
{
  sigaction (&internal, sig, info, ucontext);
}
