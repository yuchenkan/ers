#include <limits.h>
#include <stdarg.h>
#include <asm/unistd.h>

#include "recorder.h"
#include "common.h"

#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/malloc.h"
#include "lib/printf.h"
#include "lib/list.h"
#include "lib/rbtree.h"

static void
save_lock (int fd, unsigned long tid)
{
  eri_assert (eri_fwrite (fd, (const char *) &tid, sizeof tid) == 0);
}

static unsigned long
load_lock (int fd)
{
  unsigned long tid;
  size_t s;
  eri_assert (eri_fread (fd, (char *) &tid, sizeof tid, &s) == 0);
  eri_assert (s == 0 || s == sizeof tid);
  return s == 0 ? (unsigned long) -1 : tid;
}

struct lock
{
  int lock;
  int fd;

  unsigned long tid;
};

static void
init_lock (char replay, struct lock *lock, int fd)
{
  lock->lock = 0;
  lock->fd = fd;
  if (replay)
    lock->tid = load_lock (lock->fd);
}

static inline void
do_lock (int *lock)
{
  int i = 0;
  while (__atomic_exchange_n (lock, 1, __ATOMIC_ACQUIRE))
    if ((i = (i + 1) % 65536) == 0)
      ERI_ASSERT_SYSCALL (sched_yield);
}

static inline void
do_unlock (int *lock)
{
  __atomic_store_n (lock, 0, __ATOMIC_RELEASE);
}

static void
llock (char replay, unsigned long tid, struct lock *lock)
{
  if (! replay)
    {
      do_lock (&lock->lock);
      save_lock (lock->fd, tid);
    }
  else
    {
      unsigned long exp = tid;
      while (! __atomic_compare_exchange_n (&lock->tid, &exp, (unsigned long) -1, 1,
					    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	exp = tid;
    }
}

static void
lunlock (char replay, struct lock *lock)
{
  if (! replay)
    do_unlock (&lock->lock);
  else
    __atomic_store_n (&lock->tid,
		      load_lock (lock->fd), __ATOMIC_RELEASE);
}

#define ATOMIC_TYPE(type) \
  struct { struct lock lock; type val; }

#define init_atomic(atomic, fd) init_lock (&(atomic)->lock)

#define ATOMIC_FETCH_ADD(r, t, m, v) \
  ({							\
    char __r = r;					\
    unsigned long __t = t;				\
    typeof (m) __m = m;					\
    typeof (v) __v = v;					\
    llock (__r, __t, &__m->lock);			\
    typeof (__m->val) __o = __m->val;			\
    __m->val += __v;					\
    lunlock (__r, &__m->lock);				\
    __o;						\
  })

#define ATOMIC_FETCH_SUB(r, t, m, v) \
  ATOMIC_FETCH_ADD (r, t, m, -(v))
#define ATOMIC_ADD_FETCH(r, t, m, v) \
  ({ typeof (v) _v = (v); ATOMIC_FETCH_ADD (r, t, m, _v) + _v; })
#define ATOMIC_SUB_FETCH(r, t, m, v) \
  ({ typeof (v) _v = (v); ATOMIC_FETCH_SUB (r, t, m, _v) - _v; })

#define ATOMIC_COMPARE_EXCHANGE(r, t, m, e, v) \
  ({							\
    char __r = r;					\
    unsigned long __t = t;				\
    typeof (m) __m = m;					\
    typeof (e) __e = e;					\
    typeof (v) __v = v;					\
    llock (__r, __t, &__m->lock);			\
    char __ex = __m->val == __e;			\
    if (__ex) __m->val = __v;				\
    lunlock (__r, &__m->lock);				\
    __ex;						\
  })

struct sigset
{
  unsigned long val[16];
};

struct ers_thread
{
  unsigned long id;
  int *clear_tid;

  int fd;
  int log;

  ERI_LST_NODE_FIELDS (thread)

  struct sigset old_set;
};

struct atomic_lock
{
  void *mem;

  struct lock lock;
  ERI_RBT_NODE_FIELDS (atomic, struct atomic_lock)
};

struct siginfo;
struct sigact_wrap
{
  int sig;
  void *act;
  int flags;

  ERI_RBT_NODE_FIELDS (sigact, struct sigact_wrap)
};

struct internal
{
  const char *path;
  struct ers_thread *(*get_thread) (void *);
  void (*set_thread) (struct ers_thread *, void *);
  void *get_set_thread_arg;

  char printf;
  int printf_lock;

  char replay;

  ATOMIC_TYPE (long) active_lock;
  int replay_lock;

  ATOMIC_TYPE (unsigned long) lock_id;

  struct lock pool_lock;
  char *pool_buf;
  size_t pool_buf_size;
  struct eri_pool pool;

  struct lock atomics_lock;
  ERI_RBT_TREE_FIELDS (atomic, struct atomic_lock)

  ATOMIC_TYPE (unsigned long) thread_id;
  struct lock threads_lock;
  ERI_LST_LIST_FIELDS (thread)

  struct lock sigacts_lock;
  ERI_RBT_TREE_FIELDS (sigact, struct sigact_wrap)

  struct lock mmap_lock;
  struct lock brk_lock;
  unsigned long cur_brk;
};

ERI_DEFINE_RBTREE (static, atomic, struct internal, struct atomic_lock, void *, eri_less_than)
ERI_DEFINE_RBTREE (static, sigact, struct internal, struct sigact_wrap, int, eri_less_than)

ERI_DEFINE_LIST (static, thread, struct internal, struct ers_thread)

static void *
imalloc (struct internal *internal, unsigned long tid, size_t size)
{
  void *p;
  llock (internal->replay, tid, &internal->pool_lock);
  eri_assert (eri_malloc (&internal->pool, size, &p) == 0);
  lunlock (internal->replay, &internal->pool_lock);
  return p;
}

static void *
icalloc (struct internal *internal, unsigned long tid, size_t size)
{
  void *p = imalloc (internal, tid, size);
  eri_memset (p, 0, size);
  return p;
}

static void
ifree (struct internal *internal, unsigned long tid, void *p)
{
  if (! p) return;
  llock (internal->replay, tid, &internal->pool_lock);
  eri_assert (eri_free (&internal->pool, p) == 0);
  lunlock (internal->replay, &internal->pool_lock);
}

static inline struct ers_thread *
get_thread (struct internal *internal)
{
  return internal->get_thread (internal->get_set_thread_arg);
}

static inline void
set_thread (struct internal *internal, struct ers_thread *th)
{
  internal->set_thread (th, internal->get_set_thread_arg);
}

static void
iprintf (struct internal *internal, int tlog, const char *fmt, ...)
{
  va_list arg;
  if (tlog >= 0)
    {
      va_start (arg, fmt);
      eri_assert (eri_vfprintf (tlog, fmt, arg) == 0);
      va_end (arg);
    }

  if (internal->printf)
    {
      do_lock (&internal->printf_lock);
      va_start (arg, fmt);
      eri_assert (eri_vprintf (fmt, arg) == 0);
      va_end (arg);
      do_unlock (&internal->printf_lock);
    }
}

static struct ers_thread *
init_thread (struct internal *internal, unsigned long id, int *ctid)
{
  char replay = internal->replay;
  struct ers_thread *th = icalloc (internal, id, sizeof *th);

  th->id = id;
  th->clear_tid = ctid;
  th->fd = eri_open_path (internal->path, "thread-",
			  ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY,
			  th->id);
  th->log = eri_open_path (internal->path,
			   ! replay ? "record-log-" : "replay-log-",
			   ERI_OPEN_WITHID, th->id);

  iprintf (internal, th->log, "init_thread %lu %lx\n", id, th);

  llock (replay, th->id, &internal->threads_lock);
  thread_append (internal, th);
  lunlock (replay, &internal->threads_lock);
  return th;
}

static void
fini_thread (struct internal *internal, struct ers_thread *th)
{
  llock (internal->replay, th->id, &internal->threads_lock);
  thread_remove (th);
  lunlock (internal->replay, &internal->threads_lock);

  iprintf (internal, th->log, "fini_thread %lx\n", th);
  eri_assert (eri_fclose (th->log) == 0);
  eri_assert (eri_fclose (th->fd) == 0);
  ifree (internal, th->id, th);
}

asm ("  .text						\n\
  .type set_context, @function				\n\
set_context:						\n\
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
  xorb	%al, %al					\n\
  ret							\n\
  .size set_context, .-set_context			\n\
  .previous						\n"
);

/* static */ char set_context (struct eri_context *ctx);

#define ARCH_SET_FS	0x1002
#define ARCH_GET_FS	0x1003

static char
init_context (int init, unsigned long start, unsigned long end)
{
  struct eri_context ctx;
  unsigned long fs;
  ERI_ASSERT_SYSCALL (arch_prctl, ARCH_GET_FS, &fs);
  eri_save_mark (init, ERI_MARK_INIT_STACK);
  eri_save_init_map_data (init, (const char *) start, end - start);
  if (set_context (&ctx) == 0)
    {
      eri_save_init_context (init, &ctx);
      eri_assert (eri_fclose (init) == 0);
      return 0;
    }
  eri_assert (eri_fprintf (2, "replay!!!\n") == 0);
  eri_dump_maps (2);
  ERI_ASSERT_SYSCALL (munmap, ctx.unmap_start, ctx.unmap_size);
  ERI_ASSERT_SYSCALL (arch_prctl, ARCH_SET_FS, fs);
  return 1; /* replay */
}

#define S_IRWXU	0700

struct proc_map_data
{
  int init;
  unsigned long pool_start;

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
  eri_assert (eri_fprintf (2, "%lx-%lx %x\n", start, end, perms) == 0);

  if (perms & 8)
    eri_assert (eri_fprintf (2, "warning: non private map\n") == 0);

  char flags = perms & 23;
  struct proc_map_data *d = data;
  if (start == d->pool_start) flags |= 8;

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

static void
init_process (struct internal *internal)
{
  eri_assert (eri_fprintf (2, "init_process %lx\n", internal) == 0);

  const char *path = internal->path;
  if (ERI_SYSCALL_ERROR_P (ERI_SYSCALL (mkdir, path, S_IRWXU)))
    eri_assert (eri_fprintf (2, "faile to create %s\n", path) == 0);

  size_t pool_size = 64 * 1024 * 1024;
  internal->pool_buf = (char *) ERI_ASSERT_SYSCALL_RES (
		mmap, 0, pool_size, ERI_PROT_READ | ERI_PROT_WRITE,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  internal->pool_buf_size = pool_size;

  eri_assert (eri_fprintf (2, "pool_buf %lx\n", internal->pool_buf) == 0);
  eri_dump_maps (2);
  int dmp = eri_open_path (path, "maps-log", 0, 0);
  eri_dump_maps (dmp);
  eri_assert (eri_fclose (dmp) == 0);

  int init = eri_open_path (path, "init", 0, 0);
  struct proc_map_data pd = { init, (unsigned long) internal->pool_buf };
  eri_process_maps (proc_map_entry, &pd);

  eri_assert (pd.stack_start);
  char replay = internal->replay = init_context (init, pd.stack_start,
						 pd.stack_end);

  ERI_LST_INIT_LIST (thread, internal);

  unsigned long *lid = &internal->lock_id.val;
  int lfd = eri_open_path (path, "atomic-",
			   ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->active_lock.lock, lfd);

  lfd = eri_open_path (path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->lock_id.lock, lfd);

  lfd = eri_open_path (path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->pool_lock, lfd);

  eri_assert (eri_init_pool (&internal->pool,
			     internal->pool_buf,
			     internal->pool_buf_size) == 0);

  lfd = eri_open_path (path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->atomics_lock, lfd);

  lfd = eri_open_path (path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->thread_id.lock, lfd);

  lfd = eri_open_path (path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->threads_lock, lfd);

  set_thread (internal,
	      init_thread (internal, internal->thread_id.val++, 0));

  lfd = eri_open_path (path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->sigacts_lock, lfd);

  lfd = eri_open_path (path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->mmap_lock, lfd);

  lfd = eri_open_path (path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->brk_lock, lfd);
}

#define SIG_SETMASK	2
#define SIG_SETSIZE	8

static void
block_signals (struct sigset *old_set)
{
  struct sigset set;
  eri_memset (&set, 0xff, sizeof set);
  ERI_ASSERT_SYSCALL (rt_sigprocmask, SIG_SETMASK, &set, old_set, SIG_SETSIZE);
}

static void
restore_signals (const struct sigset *old_set)
{
  ERI_ASSERT_SYSCALL (rt_sigprocmask, SIG_SETMASK, old_set, 0, SIG_SETSIZE);
}

struct siginfo { char buf[128]; };
struct ucontext { char buf[168]; };

static void
save_signal (int fd, int sig, const struct siginfo *info,
	     const struct ucontext *ucontext)
{
  eri_assert (eri_fwrite (fd, (const char *) &sig, sizeof sig) == 0);
  eri_assert (eri_fwrite (fd, (const char *) info, sizeof *info) == 0);
  eri_assert (eri_fwrite (fd, (const char *) ucontext, sizeof *ucontext) == 0);
}

static void
load_signal (int fd, int *sig, struct siginfo *info,
	     struct ucontext *ucontext)
{
  eri_assert (eri_fread (fd, (char *) sig, sizeof *sig, 0) == 0);
  eri_assert (eri_fread (fd, (char *) info, sizeof *info, 0) == 0);
  eri_assert (eri_fread (fd, (char *) ucontext, sizeof *ucontext, 0) == 0);
}


/* 0 for MARK_NONE */
#define MARK_THREAD_ACTIVE 1
#define MARK_THREAD_SIGNAL 2
#define MARK_THREAD_SYSCALL 3

static void sigaction (struct internal *internal, int sig,
		       struct siginfo *info, void *ucontext);

static char
acquire_active_lock (struct internal *internal, long v, char mk)
{
  struct lock *lock = &internal->active_lock.lock;
  if (! internal->replay)
    {
      struct sigset old_set;
      block_signals (&old_set);
      do_lock (&lock->lock);
      if ((internal->active_lock.val += v) > 0)
	{
	  struct ers_thread *th = get_thread (internal);
	  eri_save_mark (th->fd, mk);
	  save_lock (lock->fd, th->id);
	  eri_memcpy (&th->old_set, &old_set, sizeof old_set);
	  do_unlock (&lock->lock);
	  return 1;
	}
      do_unlock (&lock->lock);
      restore_signals (&old_set);
      return 0;
    }
  else
    {
    retry:
      do_lock (&internal->replay_lock);
      struct ers_thread *th = get_thread (internal);
      unsigned long tid = th->id;

      char trigger_signal = 0;
      int sig;
      struct siginfo info;
      struct ucontext ucontext;

      if (mk == MARK_THREAD_ACTIVE)
	{
	  char m = eri_load_mark (th->fd);
	  eri_assert (m == ERI_MARK_NONE
		      || m == MARK_THREAD_SIGNAL
		      || m == MARK_THREAD_ACTIVE);
	  if (m == MARK_THREAD_SIGNAL)
	    {
	      trigger_signal = 1;
	      load_signal (th->fd, &sig, &info, &ucontext);
	    }
	}
      do_unlock (&internal->replay_lock);

      if (trigger_signal)
	{
	  sigaction (internal, sig, &info, &ucontext);
	  goto retry;
	}

      llock (1, tid, lock);
      eri_assert ((internal->active_lock.val += v) > 0);
      lunlock (1, lock);
      return 1;
    }
}

static void
release_active_lock (struct internal *internal, unsigned long tid,
		     long v, char exit)
{
  char replay = internal->replay;
  eri_assert (ATOMIC_SUB_FETCH (replay, tid, &internal->active_lock, v) >= 0);
  if (! replay && ! exit)
    restore_signals (&get_thread (internal)->old_set);
}

static void
check_syscall (char replay, int fd, int nr, int n, ...)
{
  long a[6];

  va_list arg;
  va_start (arg, n);
  short i = 0;
  for (i = 0; i < n; ++i)
    a[i] = (long) va_arg (arg, long);
  va_end (arg);

  if (! replay)
    {
      eri_save_mark (fd, MARK_THREAD_SYSCALL);
      eri_assert (eri_fwrite (fd, (const char *) &nr, sizeof nr) == 0);
      eri_assert (eri_fwrite (fd, (const char *) a, n * sizeof a[0]) == 0);
    }
  else
    {
      eri_assert (eri_load_mark (fd) == MARK_THREAD_SYSCALL);
      int t;
      eri_assert (eri_fread (fd, (char *) &t, sizeof t, 0) == 0);
      eri_assert (nr == t);
      long b[6];
      eri_assert (eri_fread (fd, (char *) b, n * sizeof a[0], 0) == 0);
      eri_assert (eri_strncmp ((const char *) a, (const char *) b, n * sizeof a[0]) == 0);
    }
}

static void
save_result (int fd, long res)
{
  eri_assert (eri_fwrite (fd, (const char *) &res, sizeof res) == 0);
}

static long
load_result (int fd)
{
  long res;
  eri_assert (eri_fread (fd, (char *) &res, sizeof res, 0) == 0);
  return res;
}

#define CHECK_SYSCALL(replay, fd, nr, ...) \
  check_syscall (replay, fd, nr, ERI_SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

#define SYSCALL_REC_RES(replay, fd, res, nr, ...) \
  do {									\
    if (! (replay))							\
      {									\
	*(res) = ERI_SYSCALL_NCS (nr, ##__VA_ARGS__);			\
	save_result (fd, *(res));					\
      }									\
    else *(res) = load_result (fd);					\
  } while (0)

#define SYSCALL_REC_IRES(internal, th, res, nr, ...) \
  ({									\
    char __acq = 1;							\
    release_active_lock (internal, (th)->id, 1, 0);			\
									\
    if (! (internal)->replay)						\
      *res = ERI_SYSCALL_NCS (nr, ##__VA_ARGS__);			\
									\
    if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE))	\
      __acq = 0;							\
    else if (! (internal)->replay) save_result ((th)->fd, *res);	\
    else *res = load_result ((th)->fd);					\
    __acq;								\
  })

#define CSYSCALL_REC_RES(replay, fd, res, nr, ...) \
  do {									\
    CHECK_SYSCALL (replay, fd, nr, ##__VA_ARGS__);			\
    SYSCALL_REC_RES (replay, fd, res, nr, ##__VA_ARGS__);		\
  } while (0)

#define CSYSCALL_REC_IRES(internal, th, res, nr, ...) \
  ({									\
    CHECK_SYSCALL (replay, (th)->fd, nr, ##__VA_ARGS__);		\
    SYSCALL_REC_IRES (internal, th, res, nr, ##__VA_ARGS__);		\
  })

#define SYSCALL_CHECK_RES(replay, fd, res, nr, ...) \
  do {									\
    *(res) = ERI_SYSCALL_NCS (nr, ##__VA_ARGS__);			\
    if (! (replay)) save_result (fd, *(res));				\
    else eri_assert (*(res) == load_result (fd));			\
  } while (0)

#define CSYSCALL_CHECK_RES(replay, fd, res, nr, ...) \
  do {									\
    CHECK_SYSCALL (replay, fd, nr, ##__VA_ARGS__);			\
    SYSCALL_CHECK_RES (replay, fd, res, nr, ##__VA_ARGS__);		\
  } while (0)

struct sigaction
{
  void *act;
  struct sigset mask;
  int flags;
  void (*restorer) (void);
};

static void
save_result_out (int fd, long res, const void *out, size_t size)
{
  save_result (fd, res);
  if (! ERI_SYSCALL_ERROR_P (res) && out && size)
    eri_assert (eri_fwrite (fd, out, size) == 0);
}

static void
load_result_out (int fd, long *res, void *out, size_t size)
{
  *res = load_result (fd);
  if (size == -1) size = *res;
  if (! ERI_SYSCALL_ERROR_P (*res) && out && size)
    eri_assert (eri_fread (fd, out, size, 0) == 0);
}

#define SYSCALL_REC_RES_OUT(replay, fd, res, out, nr, ...) \
  do {									\
    if (! (replay))							\
      {									\
	*(res) = ERI_SYSCALL_NCS (nr, __VA_ARGS__);			\
	save_result_out (fd, *(res), out, sizeof *out);			\
      }									\
    else load_result_out (fd, res, out, sizeof *out);			\
  } while (0)

#define CSYSCALL_REC_RES_OUT(replay, fd, res, out, nr, ...) \
  do {									\
    CHECK_SYSCALL (replay, fd, nr, __VA_ARGS__);			\
    SYSCALL_REC_RES_OUT (replay, fd, res, out, nr, __VA_ARGS__);	\
  } while (0)

static void
ent_sigaction (int sig, struct siginfo *info, void *ucontext);

#define SA_SIGINFO	4

static struct atomic_lock *
get_atomic_lock (struct internal *internal, struct ers_thread * th,
		 void *mem, char create)
{
  char replay = internal->replay;
  llock (replay, th->id, &internal->atomics_lock);
  struct atomic_lock *lock = atomic_get (internal, &mem, ERI_RBT_EQ);
  if (create && ! lock)
    {
      lock = icalloc (internal, th->id, sizeof *lock);
      lock->mem = mem;
      unsigned long lid = ATOMIC_FETCH_ADD (replay, th->id, &internal->lock_id, 1);
      int lfd = eri_open_path (internal->path, "atomic-",
			       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, lid);
      init_lock (replay, &lock->lock, lfd);
      atomic_insert (internal, lock);
    }
  lunlock (internal->replay, &internal->atomics_lock);
  return lock;
}

struct rlimit { char buf[16]; };
struct timespec { char buf[16]; };

#define FUTEX_WAIT		0
#define FUTEX_WAKE		1
#define FUTEX_WAKE_OP		5
#define FUTEX_WAIT_BITSET	9

#define FUTEX_PRIVATE_FLAG	128
#define FUTEX_CLOCK_REALTIME	256
#define FUTEX_CMD_MASK		~(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME)

#define	EINTR	4

#define SIG_DFL	((void *) 0)
#define SIG_IGN	((void *) 1)

static char __attribute__ ((used))
syscall (struct internal *internal, int nr,
	 long a1, long a2, long a3, long a4, long a5, long a6, long *res)
{
  eri_assert (nr != __NR_clone);
  if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE))
    return 0;

  char replay = internal->replay;
  struct ers_thread *th = get_thread (internal);
  unsigned long tid = th->id;
  iprintf (internal, th->log, "syscall %lu %u\n", tid, nr);

  char acq = 1;
  if (nr == __NR_exit || nr == __NR_exit_group)
    {
      CHECK_SYSCALL (replay, th->fd, nr, a1);

      char grp = tid == 0 /* main thread */
		 || nr == __NR_exit_group;
      if (grp)
	{
	  release_active_lock (internal, tid, 1, 1);
	  while (! ATOMIC_COMPARE_EXCHANGE (replay, tid, &internal->active_lock, 0,
					    LONG_MIN))
	    ERI_ASSERT_SYSCALL (sched_yield);

	  if (replay) do_lock (&internal->replay_lock);
	  iprintf (internal, th->log, "group exiting\n");

	  eri_assert (internal->brk_lock.lock == 0);
	  eri_assert (eri_fclose (internal->brk_lock.fd) == 0);

	  eri_assert (internal->mmap_lock.lock == 0);
	  eri_assert (eri_fclose (internal->mmap_lock.fd) == 0);

	  struct sigact_wrap *w, *nw;
	  ERI_RBT_FOREACH_SAFE (sigact, internal, w, nw)
	    {
	      if (! replay)
		{
		  struct sigaction act;
		  ERI_ASSERT_SYSCALL (rt_sigaction, w->sig, 0, &act);
		  eri_assert (act.act == ent_sigaction);
		  act.act = w->act;
		  act.flags = w->flags;
		  ERI_ASSERT_SYSCALL (rt_sigaction, w->sig, &act, 0);
		}

	      iprintf (internal, th->log, "remove sigact wrap %lx\n", w);
	      sigact_remove (internal, w);
	      ifree (internal, tid, w);
	    }
	  eri_assert (internal->sigacts_lock.lock == 0);
	  eri_assert (eri_fclose (internal->sigacts_lock.fd) == 0);

	  struct ers_thread *t, *nt;
	  ERI_LST_FOREACH_SAFE (thread, internal, t, nt) fini_thread (internal, t);
	  eri_assert (internal->threads_lock.lock == 0);
	  eri_assert (eri_fclose (internal->threads_lock.fd) == 0);
	  eri_assert (internal->thread_id.lock.lock == 0);
	  eri_assert (eri_fclose (internal->thread_id.lock.fd) == 0);

	  struct atomic_lock *l, *nl;
	  ERI_RBT_FOREACH_SAFE (atomic, internal, l, nl)
	    {
	      iprintf (internal, -1, "remove atomic lock %lx\n", l);
	      while (__atomic_load_n (&l->lock.lock, __ATOMIC_RELAXED)) continue;
	      eri_assert (eri_fclose (l->lock.fd) == 0);
	      atomic_remove (internal, l);
	      ifree (internal, tid, l);
	    }
	  eri_assert (internal->atomics_lock.lock == 0);
	  eri_assert (eri_fclose (internal->atomics_lock.fd) == 0);

	  iprintf (internal, -1, "used %lu\n", internal->pool.used);
	  eri_assert (eri_fini_pool (&internal->pool) == 0);
	  ERI_ASSERT_SYSCALL (munmap, internal->pool_buf, internal->pool_buf_size);
	  internal->pool_buf = 0;
	  internal->pool_buf_size = 0;

	  eri_assert (internal->pool_lock.lock == 0);
	  eri_assert (eri_fclose (internal->pool_lock.fd) == 0);

	  eri_assert (internal->lock_id.lock.lock == 0);
	  eri_assert (eri_fclose (internal->lock_id.lock.fd) == 0);

	  eri_assert (internal->active_lock.lock.lock == 0);
	  eri_assert (eri_fclose (internal->active_lock.lock.fd) == 0);
	}
      else
	{
	  if (th->clear_tid)
	    {
	      iprintf (internal, th->log, "clear_tid %lx\n", th->clear_tid);
	      struct atomic_lock *lock = get_atomic_lock (internal, th, th->clear_tid, 1);
	      llock (replay, tid, &lock->lock);
	      *th->clear_tid = 0;
	      if (! replay)
		{
		  ERI_ASSERT_SYSCALL (futex, th->clear_tid, FUTEX_WAKE, 1, 0, 0, 0);
		  /* So that it's locked until real clear_tid happens.  */
		  ERI_ASSERT_SYSCALL (set_tid_address, &lock->lock.lock);
		}
	      else
		/* Resources are not that real when replay, just release it here.  */
		lunlock (1, &lock->lock);
	    }
	  fini_thread (internal, th);
	  release_active_lock (internal, tid, 1, 1);
	}
      ERI_SYSCALL_NCS (nr, a1);
      eri_assert (0);
    }
  else if (nr == __NR_rt_sigaction)
    {
      CHECK_SYSCALL (replay, th->fd, nr, a1, a2, a3);

      int sig = (int) a1;

      struct sigact_wrap *wrap = 0;
      void *old_act = 0;
      int old_flags = 0;
      struct sigaction newact;

      const struct sigaction *act = (const struct sigaction *) a2;
      struct sigaction *old = (struct sigaction *) a3;

      llock (replay, tid, &internal->sigacts_lock);
      wrap = sigact_get (internal, &sig, ERI_RBT_EQ);

      if (old && wrap)
	{
	  old_act = wrap->act;
	  old_flags = wrap->flags;
	}

      char replace = act
		     && ((act->flags & SA_SIGINFO)
			 || (act->act != SIG_DFL && act->act != SIG_IGN));
      if (replace)
	{
	  newact.act = ent_sigaction;
	  eri_memcpy (&newact.mask, &act->mask, sizeof act->mask);
	  newact.flags = act->flags | SA_SIGINFO;
	  newact.restorer = act->restorer;
	}

      SYSCALL_REC_RES_OUT (replay, th->fd, res, old,
			   nr, sig, replace ? &newact : act, old);

      if (! ERI_SYSCALL_ERROR_P (*res))
	{
	  if (act && ! replace && wrap)
	    {
	      sigact_remove (internal, wrap);
	      ifree (internal, tid, wrap);
	    }
	  else if (act && replace)
	    {
	      if (! wrap)
		{
		  wrap = imalloc (internal, tid, sizeof *wrap);
		  wrap->sig = sig;
		  sigact_insert (internal, wrap);
		}

	      wrap->act = act->act;
	      wrap->flags = act->flags;
	    }
	}

      lunlock (replay, &internal->sigacts_lock);

      if (old && wrap && ! ERI_SYSCALL_ERROR_P (*res))
	{
	  old->act = old_act;
	  old->flags = old_flags;
	}
    }
  else if (nr == __NR_set_tid_address)
    {
      CHECK_SYSCALL (replay, th->fd, nr, a1);

      th->clear_tid = (int *) a1;
      SYSCALL_REC_RES (replay, th->fd, res, nr, a1);
    }
  else if (nr == __NR_set_robust_list)
    CSYSCALL_REC_RES (replay, th->fd, res, nr, a1, a2);
  else if (nr == __NR_rt_sigprocmask)
    CSYSCALL_REC_RES_OUT (replay, th->fd, res, (struct sigset *) a3,
			  nr, a1, a2, a3);
  else if (nr == __NR_prlimit64)
    CSYSCALL_REC_RES_OUT (replay, th->fd, res, (struct rlimit *) a4,
			  nr, a1, a2, a3, a4);
  else if (nr == __NR_clock_gettime)
    CSYSCALL_REC_RES_OUT (replay, th->fd, res, (struct timespec *) a2,
			  nr, a1, a2);
  else if (nr == __NR_read)
    {
      CHECK_SYSCALL (replay, th->fd, nr, a1, a2, a3);
      release_active_lock (internal, tid, 1, 0);

      if (! replay)
	*res = ERI_SYSCALL_NCS (nr, a1, a2, a3);

      if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE))
	acq = 0;
      else if (! replay) save_result_out (th->fd, *res, (void *) a2, *res);
      else load_result_out (th->fd, res, (void *) a2, -1);
    }
  else if (nr == __NR_write)
    acq = CSYSCALL_REC_IRES (internal, th, res, nr, a1, a2, a3);
  else if (nr == __NR_openat)
    CSYSCALL_REC_RES (replay, th->fd, res, nr, a1, a2, a3, a4);
  else if (nr == __NR_close)
    acq = CSYSCALL_REC_IRES (internal, th, res, nr, a1);
  else if (nr == __NR_mmap)
    {
      CHECK_SYSCALL (replay, th->fd, nr, a1, a2, a3, a4, a5, a6);
      llock (replay, tid, &internal->mmap_lock);
      if (! replay)
	{
	  *res = ERI_SYSCALL_NCS (nr, a1, a2, a3, a4, a5, a6);
	  save_result (th->fd, *res);
	}
      else
	{
	  *res = load_result (th->fd);
	  if (! ERI_SYSCALL_ERROR_P (*res))
	    ERI_ASSERT_SYSCALL (mmap, *res, a2, a3, a4 | ERI_MAP_FIXED,
				a5, a6);
	}
      lunlock (replay, &internal->mmap_lock);
    }
  else if (nr == __NR_mprotect)
    CSYSCALL_CHECK_RES (replay, th->fd, res, nr, a1, a2, a3);
  else if (nr == __NR_brk)
    {
      CHECK_SYSCALL (replay, th->fd, nr, a1);
      llock (replay, tid, &internal->brk_lock);

      if (! internal->cur_brk && a1)
	CSYSCALL_REC_RES (replay, th->fd, (long *) &internal->cur_brk, nr, 0);

      SYSCALL_REC_RES (replay, th->fd, res, nr, a1);
      eri_assert (! ERI_SYSCALL_ERROR_P (*res));

      if (a1 == 0)
	{
	  if (! internal->cur_brk) internal->cur_brk = (unsigned long) *res;
	  else eri_assert (internal->cur_brk == (unsigned long) *res);
	}
      else if (*res == a1)
	{
	  if (replay)
	    {
	      unsigned long c = eri_round_up (internal->cur_brk, 4096);
	      unsigned long n = eri_round_up ((unsigned long) *res, 4096);
	      if (n > c)
		ERI_ASSERT_SYSCALL (mmap, c, n - c,
				    ERI_PROT_READ | ERI_PROT_WRITE | ERI_PROT_EXEC,
				    ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS | ERI_MAP_FIXED,
				    -1, 0);
	      else if (c > n)
		ERI_ASSERT_SYSCALL (munmap, n, c - n);
	    }
	  internal->cur_brk = (unsigned long) *res;
	}

      eri_assert (internal->cur_brk);
      lunlock (replay, &internal->brk_lock);
    }
  else if (nr == __NR_munmap)
    {
      CHECK_SYSCALL (replay, th->fd, nr, a1, a2);
      llock (replay, tid, &internal->mmap_lock);
      SYSCALL_CHECK_RES (replay, th->fd, res, nr, a1, a2);
      lunlock (replay, &internal->mmap_lock);
    }
  else if (nr == __NR_futex)
    {
      int op = a2 & FUTEX_CMD_MASK;
      eri_assert (op != FUTEX_WAKE_OP); /* XXX */
      CHECK_SYSCALL (replay, th->fd, nr, a1, a2, a3, a4, a5, a6);
      if (op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET)
	release_active_lock (internal, tid, 1, 0);

      if (! replay)
	*res = ERI_SYSCALL_NCS (nr, a1, a2, a3, a4, a5, a6);

      if ((op == FUTEX_WAIT || op == FUTEX_WAIT_BITSET)
	  && ! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE))
	return 1;

      if (! replay) save_result (th->fd, *res);
      else *res = load_result (th->fd);
    }
  else if (nr == __NR_getpid)
    CSYSCALL_REC_RES (replay, th->fd, res, nr);
  else if (nr == __NR_gettid)
    CSYSCALL_REC_RES (replay, th->fd, res, nr);
  else if (nr == __NR_madvise)
    /* XXX check advice */
    CSYSCALL_REC_RES (replay, th->fd, res, nr, a1, a2, a3);
  else if (nr == __NR_time)
    CSYSCALL_REC_RES_OUT (replay, th->fd, res, (long *) a1, nr, a1);
  else
    {
      iprintf (internal, th->log, "not support %u\n", nr);
      eri_assert (0);
    }

  iprintf (internal, th->log, "syscall done %lu %u\n", tid, nr);
  if (acq) release_active_lock (internal, tid, 1, 0);
  return 1;
}

struct clone
{
  unsigned long child_id;
  struct sigset old_set;
  int *ctid;

  long res; /* replay */
};

#define CLONE_PARENT_SETTID	0x00100000
#define CLONE_CHILD_CLEARTID	0x00200000

static char __attribute__ ((used))
pre_clone (struct internal *internal, struct clone **clone,
	   long *flags, void *cstack, int *ptid, int *ctid, void *tp)
{
  if (! acquire_active_lock (internal, 2, MARK_THREAD_ACTIVE))
    return 0;

  /* VM, FS, FILES, SYSVSEM, SIGHAND, THREAD, SETTLS, PARENT_SETTID, CHILD_CLEAR_TID */
  eri_assert (*flags == 0x3d0f00);

  char replay = internal->replay;
  struct ers_thread *th = get_thread (internal);

  iprintf (internal, th->log, "pre_clone %lu\n", th->id);
  CHECK_SYSCALL (replay, th->fd, __NR_clone, flags, cstack, ptid, ctid, tp);

  *clone = imalloc (internal, th->id, sizeof **clone);
  (*clone)->child_id = ATOMIC_FETCH_ADD (replay, th->id, &internal->thread_id, 1);
  eri_memcpy (&(*clone)->old_set, &th->old_set, sizeof th->old_set);

  (*clone)->ctid = ctid;

  if (replay)
    {
      (*clone)->res = load_result (th->fd);
      eri_assert ((*clone)->res);
      if (ERI_SYSCALL_ERROR_P ((*clone)->res))
	{
	  iprintf (internal, th->log, "pre_clone down %lu\n", th->id);
	  return 2;
	}

      *flags &= ~(CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID);
      *ptid = (*clone)->res;
    }
  iprintf (internal, th->log, "pre_clone down %lu\n", th->id);
  return 1;
}

static long __attribute__ ((used))
post_clone (struct internal *internal, struct clone *clone, long res)
{
  char replay = internal->replay;
  struct ers_thread *th = res == 0 ? 0 : get_thread (internal);
  if (res != 0)
    iprintf (internal, th->log,
	     "post_clone %lu %lu\n", th->id, ! replay ? res : clone->res);

  if (! replay)
    {
      if (res != 0)
	save_result (th->fd, res);
    }
  else
    {
      if (ERI_SYSCALL_ERROR_P (clone->res)) /* clone shall fail, no syscall */
	res = clone->res;
      else if (ERI_SYSCALL_ERROR_P (res)) /* clone should not fail */
	{
	  eri_assert (eri_fprintf (2, "failed to clone thread\n") == 0);
	  eri_assert (0);
	}
      else if (res != 0) /* clone succeeded and we are the parent, replace the result */
	{
	  res = clone->res;
	  __atomic_store_n (&clone->res, 0, __ATOMIC_RELEASE);
	}
    }

  long rel = 1;
  if (ERI_SYSCALL_ERROR_P (res))
    {
      ifree (internal, th->id, clone);
      rel = 2;
    }
  else if (res == 0)
    {
      th = init_thread (internal, clone->child_id, clone->ctid);
      iprintf (internal, th->log,
	       "post_clone %lu %lu\n", th->id, 0);
      set_thread (internal, th);
      eri_memcpy (&th->old_set, &clone->old_set, sizeof th->old_set);

      if (replay)
	while (__atomic_load_n (&clone->res, __ATOMIC_ACQUIRE) != 0)
	  continue;
      ifree (internal, th->id, clone);
    }

  iprintf (internal, th->log, "post_clone done %lu\n", th->id);
  release_active_lock (internal, th->id, rel, 0);
  return res;
}

static void
sigaction (struct internal *internal, int sig, struct siginfo *info, void *ucontext)
{
  char replay = internal->replay;

  void *act;
  int flags;
  if (acquire_active_lock (internal, 1, MARK_THREAD_SIGNAL))
    {
      struct ers_thread *th = get_thread (internal);
      iprintf (internal, th->log, "sigaction %lu %u\n", th->id, sig);

      if (! replay) save_signal (th->fd, sig, info, ucontext);

      llock (internal->replay, th->id, &internal->sigacts_lock);

      struct sigact_wrap *wrap = sigact_get (internal, &sig, ERI_RBT_EQ);
      eri_assert (wrap);
      act = wrap->act;
      flags = wrap->flags;

      lunlock (internal->replay, &internal->sigacts_lock);
      iprintf (internal, th->log, "sigaction done %lu %u\n", th->id, sig);
      release_active_lock (internal, th->id, 1, 0);
    }
  else
    {
      /* Dead loop inside acquire_active_lock if replay */
      eri_assert (! replay);

      struct sigaction a;
      while (1)
	{
	  ERI_ASSERT_SYSCALL (rt_sigaction, sig, 0, &a);
	  if (a.act != ent_sigaction) break;
	}
      act = a.act;
      flags = a.flags;
    }

    if (flags & SA_SIGINFO)
      ((void (*) (int, struct siginfo *, void *)) act) (sig, info, ucontext);
    else
      ((void (*) (int)) act) (sig);
}

static char
atomic_lock (struct internal *internal, void *mem)
{
  if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE)) return 0;

  struct ers_thread *th = get_thread (internal);
  iprintf (internal, th->log, "atomic_lock %lu %lx\n", th->id, mem);

  struct atomic_lock *lock = get_atomic_lock (internal, th, mem, 1);
  llock (internal->replay, th->id, &lock->lock);
  iprintf (internal, th->log, "atomic_lock done %lu %lx\n", th->id, mem);
  return 1;
}

static void
atomic_unlock (struct internal *internal, void *mem, int mo)
{
  struct ers_thread *th = get_thread (internal);
  iprintf (internal, th->log, "atomic_unlock %lu %lx %u\n", th->id, mem, mo);

  struct atomic_lock *lock = get_atomic_lock (internal, th, mem, 0);
  eri_assert (lock);
  lunlock (internal->replay, &lock->lock);
  iprintf (internal, th->log, "atomic_unlock done %lu %lx %u\n", th->id, mem, mo);
  release_active_lock (internal, th->id, 1, 0);
}

static char
atomic_barrier (struct internal *internal, int mo)
{
#if 0
  if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE)) return 0;
  struct ers_thread *th = get_thread (internal);
  iprintf (internal, th->log, "atomic_barrier %lu %u\n", th->id, mo);

  release_active_lock (internal, th->id, 1, 0);
  return 1;
#endif
  return 0;
}

static struct internal internal;
static char initialized;

static void
ent_init_process (const char *path,
		  struct ers_thread *(*get) (void *),
		  void (*set) (struct ers_thread *, void *),
		  void *arg)
{
  internal.path = path;
  internal.get_thread = get;
  internal.set_thread = set;
  internal.get_set_thread_arg = arg;
  /* internal->printf = 1; */

  init_process (&internal);
  initialized = 1;
}

/* static */ char ent_syscall (int nr, long a1, long a2, long a3, long a4,
			       long a5, long a6, long *res);

asm ("  .text							\n\
  .type ent_syscall, @function					\n\
ent_syscall:							\n\
  .cfi_startproc						\n\
								\n\
  cmpb	$0, initialized(%rip)					\n\
  movb	$0, %al							\n\
  je	.return1						\n\
								\n\
  cmpl	$" _ERS_STR (__NR_clone) ", %edi			\n\
  je	.call_clone						\n\
								\n\
  pushq	16(%rsp)		/* res */			\n\
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
								\n\
.return1:							\n\
  ret								\n\
								\n\
.call_clone:							\n\
  call .clone							\n\
  .cfi_endproc							\n\
								\n\
.clone:								\n\
  .cfi_startproc						\n\
  subq	$8, %rsp		/* alignment, clone */		\n\
  .cfi_adjust_cfa_offset 8					\n\
  pushq	%rsi			/* flags */			\n\
  .cfi_adjust_cfa_offset 8					\n\
  pushq	%rdx			/* cstack */			\n\
  .cfi_adjust_cfa_offset 8					\n\
  pushq	%rcx			/* ptid */			\n\
  .cfi_adjust_cfa_offset 8					\n\
  pushq	%r8			/* ctid */			\n\
  .cfi_adjust_cfa_offset 8					\n\
  pushq	%r9			/* tp */			\n\
  .cfi_adjust_cfa_offset 8					\n\
								\n\
  movq	%r8, %r9		/* ctid */			\n\
  movq	%rcx, %r8		/* ptid */			\n\
  movq	%rdx, %rcx		/* cstack */			\n\
  leaq	32(%rsp), %rdx		/* &flags */			\n\
  leaq	40(%rsp), %rsi		/* &clone */			\n\
  leaq	internal(%rip), %rdi	/* internal */			\n\
  call	pre_clone						\n\
  testb	 %al, %al						\n\
  jz	.return2						\n\
								\n\
  cmpb	$2, %al			/* replay & no syscall */	\n\
  je	.post							\n\
								\n\
  movq	(%rsp), %r8		/* tp */			\n\
  movq	8(%rsp), %r10		/* ctid */			\n\
  movq	16(%rsp), %rdx		/* ptid */			\n\
  movq	24(%rsp), %rsi		/* cstack */			\n\
  movq	32(%rsp), %rdi		/* flags */			\n\
								\n\
  subq	$16, %rsi						\n\
  movq	56(%rsp), %rax						\n\
  movq	%rax, 8(%rsi)		/* return address */		\n\
  movq	40(%rsp), %rax						\n\
  movq	%rax, (%rsi)		/* clone */			\n\
								\n\
  movl	$" _ERS_STR (__NR_clone) ", %eax	/* nr_clone */	\n\
  syscall							\n\
  .cfi_undefined %rip						\n\
								\n\
  testq	%rax, %rax						\n\
  jz	.child							\n\
  .cfi_restore %rip						\n\
								\n\
.post:								\n\
  movq	%rax, %rdx		/* *res */			\n\
  movq	40(%rsp), %rsi		/* clone */			\n\
  leaq	internal(%rip), %rdi	/* internal */			\n\
  call	post_clone						\n\
  movq	72(%rsp), %rdi		/* res */			\n\
  movq	%rax, (%rdi)						\n\
								\n\
.return2:							\n\
  movb	$1, %al							\n\
  addq	$56, %rsp						\n\
  .cfi_adjust_cfa_offset -56					\n\
  .cfi_rel_offset %rip, 0					\n\
  ret								\n\
								\n\
.child:								\n\
  .cfi_undefined %rip						\n\
  movq	$0, %rdx		/* *res */			\n\
  movq	(%rsp), %rsi		/* clone */			\n\
  leaq	internal(%rip), %rdi	/* internal */			\n\
  call	post_clone						\n\
  addq	$8, %rsp						\n\
  movb	$2, %al							\n\
  ret								\n\
  .cfi_endproc							\n\
  .size ent_syscall, .-ent_syscall				\n\
  .previous							\n"
);

static char
ent_atomic_lock (void *mem)
{
  return initialized && atomic_lock (&internal, mem);
}

static void
ent_atomic_unlock (void *mem, int mo)
{
  atomic_unlock (&internal, mem, mo);
}

static char
ent_atomic_barrier (int mo)
{
  return initialized && atomic_barrier (&internal, mo);
}

static struct ers_recorder recorder = {

  ent_init_process,
  ent_syscall,
  ent_atomic_lock,
  ent_atomic_unlock,
  ent_atomic_barrier
};

__attribute__ ((visibility ("default"))) struct ers_recorder *
ers_get_recorder (void)
{
  return &recorder;
}

static void
ent_sigaction (int sig, struct siginfo *info, void *ucontext)
{
  sigaction (&internal, sig, info, ucontext);
}
