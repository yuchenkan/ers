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
  while (__atomic_exchange_n (lock, 1, __ATOMIC_ACQUIRE))
    continue;
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
    while (__atomic_load_n (&lock->tid, __ATOMIC_ACQUIRE) != tid)
      continue;
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

static struct ers_thread *
init_thread (struct internal *internal, unsigned long id, int *ctid)
{
  char replay = internal->replay;
  struct ers_thread *th = icalloc (internal, id, sizeof *th);

  eri_assert (eri_printf ("init_thread %lx\n", th) == 0);

  th->id = id;
  th->clear_tid = ctid;
  th->fd = eri_open_path (internal->path, "thread-",
			  ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY,
			  th->id);

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

  eri_assert (eri_printf ("fini_thread %lx\n", th) == 0);
  eri_assert (eri_fclose (th->fd) == 0);
  ifree (internal, th->id, th);
}

asm ("  .text\n\
  .type	set_context, @function\n\
set_context:\n\
  movq	%rbx, (%rdi)\n\
  movq	%rbp, 8(%rdi)\n\
  movq	%r12, 16(%rdi)\n\
  movq	%r13, 24(%rdi)\n\
  movq	%r14, 32(%rdi)\n\
  movq	%r15, 40(%rdi)\n\
\n\
  movq	%rdi, 48(%rdi)\n\
  movq	%rsi, 56(%rdi)\n\
  movq	%rdx, 64(%rdi)\n\
  movq	%rcx, 72(%rdi)\n\
  movq	%r8, 80(%rdi)\n\
  movq	%r9, 88(%rdi)\n\
\n\
  movq	(%rsp), %rcx\n\
  movq	%rcx, 96(%rdi)		/* %rip */\n\
  leaq	8(%rsp), %rcx\n\
  movq	%rcx, 104(%rdi)		/* %rsp */\n\
\n\
  leaq	112(%rdi), %rcx\n\
  fnstenv	(%rcx)\n\
  fldenv	(%rcx)\n\
  stmxcsr	136(%rdi)\n\
\n\
  xorb	%al, %al\n\
  ret\n\
  .size	set_context, .-set_context\n"
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
  eri_assert (eri_printf ("replay!!!\n") == 0);
  eri_dump_maps ();
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
  eri_assert (eri_printf ("%lx-%lx %x\n", start, end, perms) == 0);

  if (perms & 8)
    eri_assert (eri_printf ("warning: non private map\n") == 0);

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
  eri_assert (eri_printf ("init_process %lx\n", internal) == 0);

  ERI_ASSERT_SYSCALL (mkdir, internal->path, S_IRWXU);

  size_t pool_size = 64 * 1024 * 1024;
  internal->pool_buf = (char *) ERI_ASSERT_SYSCALL_RES (
		mmap, 0, pool_size, ERI_PROT_READ | ERI_PROT_WRITE,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  internal->pool_buf_size = pool_size;

  eri_assert (eri_printf ("pool_buf %lx\n", internal->pool_buf) == 0);
  eri_dump_maps ();

  int init = eri_open_path (internal->path, "init", 0, 0);
  struct proc_map_data pd = { init, (unsigned long) internal->pool_buf };
  eri_process_maps (proc_map_entry, &pd);

  eri_assert (pd.stack_start);
  char replay = internal->replay = init_context (init, pd.stack_start,
						 pd.stack_end);

  ERI_LST_INIT_LIST (thread, internal);

  unsigned long *lid = &internal->lock_id.val;
  int lfd = eri_open_path (internal->path, "atomic-",
			   ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->active_lock.lock, lfd);

  lfd = eri_open_path (internal->path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->lock_id.lock, lfd);

  lfd = eri_open_path (internal->path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);

  init_lock (replay, &internal->pool_lock, lfd);

  eri_assert (eri_init_pool (&internal->pool,
			     internal->pool_buf,
			     internal->pool_buf_size) == 0);

  lfd = eri_open_path (internal->path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->atomics_lock, lfd);

  lfd = eri_open_path (internal->path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->thread_id.lock, lfd);

  lfd = eri_open_path (internal->path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->threads_lock, lfd);

  set_thread (internal,
	      init_thread (internal, internal->thread_id.val++, 0));

  lfd = eri_open_path (internal->path, "atomic-",
		       ERI_OPEN_WITHID | replay * ERI_OPEN_REPLAY, (*lid)++);
  init_lock (replay, &internal->sigacts_lock, lfd);

  lfd = eri_open_path (internal->path, "atomic-",
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

      unsigned long exp = tid;
      while (! __atomic_compare_exchange_n (&lock->tid, &exp, (unsigned long) -1, 1,
					    __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	exp = tid;
      eri_assert ((internal->active_lock.val += v) > 0);
      __atomic_store_n (&lock->tid,
			load_lock (lock->fd), __ATOMIC_RELEASE);
      return 1;
    }
}

static void
release_active_lock (struct internal *internal, long v, char exit)
{
  char replay = internal->replay;
  struct ers_thread *th = get_thread (internal);
  eri_assert (ATOMIC_SUB_FETCH (replay, th->id, &internal->active_lock, v) >= 0);
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
save_return (int fd, long ret)
{
  eri_assert (eri_fwrite (fd, (const char *) &ret, sizeof ret) == 0);
}

static long
load_return (int fd)
{
  long ret;
  eri_assert (eri_fread (fd, (char *) &ret, sizeof ret, 0) == 0);
  return ret;
}

#define CHECK_SYSCALL(replay, fd, nr, ...) \
  check_syscall (replay, fd, nr, ERI_SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

#define SYSCALL_REC_RET(replay, fd, ret, nr, ...) \
  do {								\
    if (! (replay))						\
      {								\
	*(ret) = ERI_SYSCALL_NCS (nr, ##__VA_ARGS__);		\
	save_return (fd, *(ret));				\
      }								\
    else *(ret) = load_return (fd);				\
  } while (0)

#define CSYSCALL_REC_RET(replay, fd, ret, nr, ...) \
  do {								\
    CHECK_SYSCALL (replay, fd, nr, ##__VA_ARGS__);		\
    SYSCALL_REC_RET (replay, fd, ret, nr, ##__VA_ARGS__);	\
  } while (0)

#define CSYSCALL_CHECK_RET(replay, fd, ret, nr, ...) \
  do {								\
    CHECK_SYSCALL (replay, fd, nr, ##__VA_ARGS__);		\
    *(ret) = ERI_SYSCALL_NCS (nr, ##__VA_ARGS__);		\
    if (! (replay)) save_return (fd, *(ret));			\
    else eri_assert (*(ret) == load_return (fd));		\
  } while (0)

struct sigaction
{
  void *act;
  struct sigset mask;
  int flags;
  void (*restorer) (void);
};

static void
save_return_out (int fd, long ret, const void *old, size_t size)
{
  save_return (fd, ret);
  if (! ERI_SYSCALL_ERROR_P (ret) && old)
    eri_assert (eri_fwrite (fd, old, size) == 0);
}

static void
load_return_out (int fd, long *ret, void *old, size_t size)
{
  *ret = load_return (fd);
  if (! ERI_SYSCALL_ERROR_P (*ret) && old)
    eri_assert (eri_fread (fd, old, size, 0) == 0);
}

#define SYSCALL_REC_RET_OLD(replay, fd, ret, out, nr, ...) \
  do {									\
    if (! (replay))							\
      {									\
	*(ret) = ERI_SYSCALL_NCS (nr, __VA_ARGS__);			\
	save_return_out (fd, *(ret), out, sizeof *out);			\
      }									\
    else load_return_out (fd, (ret), out, sizeof *out);			\
  } while (0)

#define CSYSCALL_REC_RET_OLD(replay, fd, ret, out, nr, ...) \
  do {									\
    CHECK_SYSCALL (replay, fd, nr, __VA_ARGS__);			\
    SYSCALL_REC_RET_OLD (replay, fd, ret, out, nr, __VA_ARGS__);	\
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

#define FUTEX_WAKE	1
#define FUTEX_WAKE_OP	5

#define	EINTR	4

#define SIG_DFL	((void *) 0)
#define SIG_IGN	((void *) 1)

static char __attribute__ ((used))
syscall (struct internal *internal, int nr,
	 long a1, long a2, long a3, long a4, long a5, long a6, long *ret)
{
  eri_assert (eri_printf ("syscall %u\n", nr) == 0);
  eri_assert (nr != __NR_clone);
  if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE))
    return 0;

  char replay = internal->replay;
  struct ers_thread *th = get_thread (internal);

  if (nr == __NR_exit || nr == __NR_exit_group)
    {
      check_syscall (replay, th->fd, nr, 1, a1);

      char grp = th->id == 0 /* main thread */
		 || nr == __NR_exit_group;
      if (grp)
	{
	  release_active_lock (internal, 1, 1);
	  while (! ATOMIC_COMPARE_EXCHANGE (replay, th->id, &internal->active_lock, 0,
					    LONG_MIN))
	    if (! replay) ERI_ASSERT_SYSCALL (sched_yield);
	  eri_assert (eri_printf ("group exiting\n") == 0);

	  if (replay) do_lock (&internal->replay_lock);

	  eri_assert (internal->brk_lock.lock == 0);
	  eri_assert (eri_fclose (internal->brk_lock.fd) == 0);

	  struct sigact_wrap *w, *nw;
	  ERI_RBT_FOREACH_SAFE (sigact, internal, w, nw)
	    {
	      if (!replay)
		{
		  struct sigaction act;
		  ERI_ASSERT_SYSCALL (rt_sigaction, w->sig, 0, &act);
		  eri_assert (act.act == ent_sigaction);
		  act.act = w->act;
		  act.flags = w->flags;
		  ERI_ASSERT_SYSCALL (rt_sigaction, w->sig, &act, 0);
		}

	      eri_assert (eri_printf ("remove sigact wrap %lx\n", w) == 0);
	      sigact_remove (internal, w);
	      ifree (internal, th->id, w);
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
	      eri_assert (eri_printf ("remove atomic lock %lx\n", l) == 0);
	      while (__atomic_load_n (&l->lock.lock, __ATOMIC_RELAXED)) continue;
	      eri_assert (eri_fclose (l->lock.fd) == 0);
	      atomic_remove (internal, l);
	      ifree (internal, th->id, l);
	    }
	  eri_assert (internal->atomics_lock.lock == 0);
	  eri_assert (eri_fclose (internal->atomics_lock.fd) == 0);

	  eri_assert (eri_printf ("used %lu\n", internal->pool.used) == 0);
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
	      eri_assert (eri_printf ("clear_tid %lx\n", th->clear_tid) == 0);
	      struct atomic_lock *lock = get_atomic_lock (internal, th, th->clear_tid, 1);
	      llock (replay, th->id, &lock->lock);
	      *th->clear_tid = 0;
	      if (! replay)
		{
		  ERI_ASSERT_SYSCALL (futex, th->clear_tid, FUTEX_WAKE, 1, 0, 0, 0);
		  /* So that it's locked until real clear_tid happens.  */
		  ERI_ASSERT_SYSCALL (set_tid_address, &lock->lock.lock);
		}
	      else
		/* Resources are not that real when replay, just release it here.  */
		lunlock (replay, &lock->lock);
	    }
	  fini_thread (internal, th);
	  release_active_lock (internal, 1, 1);
	}
      ERI_SYSCALL_NCS (nr, a1);
      eri_assert (0);
    }
  else if (nr == __NR_rt_sigaction)
    {
      check_syscall (replay, th->fd, nr, 3, a1, a2, a3);

      int sig = (int) a1;

      struct sigact_wrap *wrap;
      void *old_act = 0;
      int old_flags = 0;
      char replace = 0;
      struct sigaction newact;

      const struct sigaction *act = (const struct sigaction *) a2;
      struct sigaction *old = (struct sigaction *) a3;
      if (act || old)
	{
	  llock (replay, th->id, &internal->sigacts_lock);
	  wrap = sigact_get (internal, &sig, ERI_RBT_EQ);
	}

      if (old && wrap)
	{
	  old_act = wrap->act;
	  old_flags = wrap->flags;
	}

      if (act)
	{
	  if (! (act->flags & SA_SIGINFO)
	      && (act->act == SIG_DFL || act->act == SIG_IGN))
	    {
	      if (wrap)
		{
		  sigact_remove (internal, wrap);
		  ifree (internal, th->id, wrap);
		}
	    }
	  else
	    {
	      if (! wrap)
		{
		  wrap = imalloc (internal, th->id, sizeof *wrap);
		  wrap->sig = sig;
		  sigact_insert (internal, wrap);
		}

	      wrap->act = act->act;
	      wrap->flags = act->flags;

	      newact.act = ent_sigaction;
	      eri_memcpy (&newact.mask, &act->mask, sizeof act->mask);
	      newact.flags = act->flags | SA_SIGINFO;
	      newact.restorer = act->restorer;
	      replace = 1;
	    }
	}

      SYSCALL_REC_RET_OLD (replay, th->fd, ret, old,
			   nr, sig, replace ? &newact : act, old);

      if (act || old) lunlock (replay, &internal->sigacts_lock);

      if (old && wrap && ! ERI_SYSCALL_ERROR_P (*ret))
	{
	  old->act = old_act;
	  old->flags = old_flags;
	}
    }
  else if (nr == __NR_set_tid_address)
    {
      CHECK_SYSCALL (replay, th->fd, nr, a1);

      th->clear_tid = (int *) a1;
      SYSCALL_REC_RET (replay, th->fd, ret, nr, a1);
    }
  else if (nr == __NR_set_robust_list)
    CSYSCALL_REC_RET (replay, th->fd, ret, nr, a1, a2);
  else if (nr == __NR_rt_sigprocmask)
    CSYSCALL_REC_RET_OLD (replay, th->fd, ret, (struct sigset *) a3,
			  nr, a1, a2, a3);
  else if (nr == __NR_prlimit64)
    CSYSCALL_REC_RET_OLD (replay, th->fd, ret, (struct rlimit *) a4,
			  nr, a1, a2, a3, a4);
  else if (nr == __NR_clock_gettime)
    CSYSCALL_REC_RET_OLD (replay, th->fd, ret, (struct timespec *) a2,
			  nr, a1, a2);
  else if (nr == __NR_write)
    {
      check_syscall (replay, th->fd, nr, 3, a1, a2, a3);
      release_active_lock (internal, 1, 0);

      if (! replay)
	*ret = ERI_SYSCALL_NCS (nr, a1, a2, a3);

      if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE))
	return 1;
      if (! replay) save_return (th->fd, *ret);
      else *ret = load_return (th->fd);
    }
  else if (nr == __NR_mmap)
    {
      CHECK_SYSCALL (replay, th->fd, nr, a1, a2, a3, a4, a5, a6);
      if (! replay)
	{
	  *ret = ERI_SYSCALL_NCS (nr, a1, a2, a3, a4, a5, a6);
	  save_return (th->fd, *ret);
	}
      else
	{
	  *ret = load_return (th->fd);
	  if (! ERI_SYSCALL_ERROR_P (*ret))
	    ERI_ASSERT_SYSCALL (mmap, *ret, a2, a3, a4 | ERI_MAP_FIXED,
				a5, a6);
	}
    }
  else if (nr == __NR_mprotect)
    CSYSCALL_CHECK_RET (replay, th->fd, ret, nr, a1, a2, a3);
  else if (nr == __NR_brk)
    {
      CHECK_SYSCALL (replay, th->fd, nr, a1);
      llock (replay, th->id, &internal->brk_lock);

      if (! internal->cur_brk && a1)
	CSYSCALL_REC_RET (replay, th->fd, (long *) &internal->cur_brk, nr, 0);

      SYSCALL_REC_RET (replay, th->fd, ret, nr, a1);
      eri_assert (! ERI_SYSCALL_ERROR_P (*ret));

      if (a1 == 0)
	{
	  if (! internal->cur_brk) internal->cur_brk = (unsigned long) *ret;
	  else eri_assert (internal->cur_brk == (unsigned long) *ret);
	}
      else if (*ret == a1)
	{
	  if (replay)
	    {
	      unsigned long c = eri_round_up (internal->cur_brk, 4096);
	      unsigned long n = eri_round_up ((unsigned long) *ret, 4096);
	      if (n > c)
		ERI_ASSERT_SYSCALL (mmap, c, n - c,
				    ERI_PROT_READ | ERI_PROT_WRITE | ERI_PROT_EXEC,
				    ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS | ERI_MAP_FIXED,
				    -1, 0);
	      else if (c > n)
		ERI_ASSERT_SYSCALL (munmap, n, c - n);
	    }
	  internal->cur_brk = (unsigned long) *ret;
	}

      eri_assert (internal->cur_brk);
      lunlock (replay, &internal->brk_lock);
    }
  else if (nr == __NR_munmap)
    CSYSCALL_CHECK_RET (replay, th->fd, ret, nr, a1, a2);
  else if (nr == __NR_futex)
    {
      eri_assert ((a2 & FUTEX_WAKE_OP) == 0); /* XXX */
      check_syscall (replay, th->fd, nr, 6, a1, a2, a3, a4, a5, a6);
      release_active_lock (internal, 1, 0);

      if (! replay)
	*ret = ERI_SYSCALL_NCS (nr, a1, a2, a3, a4, a5, a6);

      if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE))
	return 1;

      if (! replay) save_return (th->fd, *ret);
      else *ret = load_return (th->fd);
    }
  else if (nr == __NR_getpid)
    CSYSCALL_REC_RET (replay, th->fd, ret, nr);
  else if (nr == __NR_madvise)
    /* XXX check advice */
    CSYSCALL_REC_RET (replay, th->fd, ret, nr, a1, a2, a3);
  else
    {
      eri_assert (eri_printf ("not support %u\n", nr));
      eri_assert (0);
    }

  release_active_lock (internal, 1, 0);
  eri_assert (eri_printf ("syscall done %u\n", nr) == 0);
  return 1;
}

struct clone
{
  unsigned long child_id;
  struct sigset old_set;
  int *ctid;

  long ret; /* replay */
};

#define CLONE_PARENT_SETTID	0x00100000
#define CLONE_CHILD_CLEARTID	0x00200000

static char __attribute__ ((used))
pre_clone (struct internal *internal, struct clone **clone,
	   long *flags, void *cstack, int *ptid, int *ctid, void *tp)
{
  eri_assert (eri_printf ("pre_clone\n") == 0);
  if (! acquire_active_lock (internal, 2, MARK_THREAD_ACTIVE))
    return 0;

  /* VM, FS, FILES, SYSVSEM, SIGHAND, THREAD, SETTLS, PARENT_SETTID, CHILD_CLEAR_TID */
  eri_assert (*flags == 0x3d0f00);

  char replay = internal->replay;
  struct ers_thread *th = get_thread (internal);
  check_syscall (replay, th->fd, __NR_clone, 5, flags, cstack, ptid, ctid, tp);

  *clone = imalloc (internal, th->id, sizeof **clone);
  (*clone)->child_id = ATOMIC_FETCH_ADD (replay, th->id, &internal->thread_id, 1);
  eri_memcpy (&(*clone)->old_set, &th->old_set, sizeof th->old_set);

  (*clone)->ctid = ctid;

  if (replay)
    {
      (*clone)->ret = load_return (th->fd);
      if (ERI_SYSCALL_ERROR_P ((*clone)->ret))
	return 2;

      *flags &= ~(CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID);
      *ptid = (*clone)->ret;
    }
  return 1;
}

static long __attribute__ ((used))
post_clone (struct internal *internal, struct clone *clone, long ret)
{
  char replay = internal->replay;
  eri_assert (eri_printf ("post_clone %lu\n",
			  ! replay || ret == 0 ? ret : clone->ret) == 0);

  if (! replay)
    {
      if (ret != 0)
	save_return (get_thread (internal)->fd, ret);
    }
  else
    {
      if (ERI_SYSCALL_ERROR_P (clone->ret)) /* clone shall fail, no syscall */
	ret = clone->ret;
      else if (ERI_SYSCALL_ERROR_P (ret)) /* clone should not afil */
	{
	  eri_assert (eri_printf ("failed to clone thread\n") == 0);
	  eri_assert (0);
	}
      else if (ret != 0) /* clone succeeded, replace the return value */
	ret = clone->ret;
    }

  if (ERI_SYSCALL_ERROR_P (ret))
    {
      ifree (internal, get_thread (internal)->id, clone);
      release_active_lock (internal, 2, 0);
    }
  else if (ret == 0)
    {
      struct ers_thread *th = init_thread (internal, clone->child_id,
					   clone->ctid);
      set_thread (internal, th);
      eri_memcpy (&th->old_set, &clone->old_set, sizeof th->old_set);
      ifree (internal, th->id, clone);

      release_active_lock (internal, 1, 0);
    }
  else release_active_lock (internal, 1, 0);
  return ret;
}

static void
sigaction (struct internal *internal, int sig, struct siginfo *info, void *ucontext)
{
  eri_assert (eri_printf ("sigaction %u\n", sig) == 0);

  char replay = internal->replay;

  void *act;
  int flags;
  if (acquire_active_lock (internal, 1, MARK_THREAD_SIGNAL))
    {
      struct ers_thread *th = get_thread (internal);
      if (! replay) save_signal (th->fd, sig, info, ucontext);

      llock (internal->replay, th->id, &internal->sigacts_lock);

      struct sigact_wrap *wrap = sigact_get (internal, &sig, ERI_RBT_EQ);
      eri_assert (wrap);
      act = wrap->act;
      flags = wrap->flags;

      lunlock (internal->replay, &internal->sigacts_lock);
      release_active_lock (internal, 1, 0);
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
  eri_assert (eri_printf ("atomic_lock %lx\n", mem) == 0);
  if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE)) return 0;

  struct ers_thread *th = get_thread (internal);

  struct atomic_lock *lock = get_atomic_lock (internal, th, mem, 1);
  llock (internal->replay, th->id, &lock->lock);
  eri_assert (eri_printf ("atomic_lock done %lx\n", mem) == 0);
  return 1;
}

static void
atomic_unlock (struct internal *internal, void *mem, int mo)
{
  eri_assert (eri_printf ("atomic_unlock %lx %u\n", mem, mo) == 0);
  struct ers_thread *th = get_thread (internal);

  struct atomic_lock *lock = get_atomic_lock (internal, th, mem, 0);
  eri_assert (lock);
  lunlock (internal->replay, &lock->lock);
  release_active_lock (internal, 1, 0);
  eri_assert (eri_printf ("atomic_unlock done %lx %u\n", mem, mo) == 0);
}

static char
atomic_barrier (struct internal *internal, int mo)
{
  eri_assert (eri_printf ("atomic_barrier %u\n", mo) == 0);
  if (! acquire_active_lock (internal, 1, MARK_THREAD_ACTIVE)) return 0;

  release_active_lock (internal, 1, 0);
  return 1;
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

  init_process (&internal);
  initialized = 1;
}

#if 1
/* static */ char ent_syscall (int nr, long a1, long a2, long a3, long a4,
			       long a5, long a6, long *ret);

asm ("  .text\n\
  .type	ent_syscall, @function\n\
ent_syscall:\n\
  .cfi_startproc\n\
  pushq	%rbp\n\
  .cfi_def_cfa_offset 16\n\
  .cfi_offset 6, -16\n\
  movq	%rsp, %rbp\n\
  .cfi_def_cfa_register 6\n\
  movb	initialized(%rip), %al\n\
  testb	%al, %al\n\
  jz	.leave\n\
\n\
  subq	$56, %rsp\n\
  movl	%edi, -4(%rbp)		/* nr */\n\
  movq	%rsi, -16(%rbp)		/* a1 */\n\
  movq	%rdx, -24(%rbp)		/* a2 */\n\
  movq	%rcx, -32(%rbp)		/* a3 */\n\
  movq	%r8, -40(%rbp)		/* a4 */\n\
  movq	%r9, -48(%rbp)		/* a5 */\n\
  movq	16(%rbp), %rax\n\
  movq	%rax, -56(%rbp)		/* a6 */\n\
\n\
  cmpl	$"ERI_STRINGIFY (__NR_clone)", -4(%rbp)\n\
  je	.clone\n\
  pushq	24(%rbp)		/* ret */\n\
  pushq	-56(%rbp)		/* a6 */\n\
  pushq	-48(%rbp)		/* a5 */\n\
  movq	-40(%rbp), %r9		/* a4 */\n\
  movq	-32(%rbp), %r8		/* a3 */\n\
  movq	-24(%rbp), %rcx		/* a2 */\n\
  movq	-16(%rbp), %rdx		/* a1 */\n\
  movl	-4(%rbp), %esi		/* nr */\n\
  leaq	internal(%rip), %rdi	/* internal */\n\
  call	syscall\n\
  addq	$80,  %rsp\n\
  jmp	.leave\n\
.clone:\n\
  subq	$16, %rsp		/* -64(%rbp) clone, aligment */\n\
  pushq	-48(%rbp)		/* tp */\n\
  movq	-40(%rbp), %r9		/* ctid */\n\
  movq	-32(%rbp), %r8		/* ptid */\n\
  movq	-24(%rbp), %rcx		/* cstack */\n\
  leaq	-16(%rbp), %rdx		/* &flags */\n\
  leaq	-64(%rbp), %rsi		/* &clone */\n\
  leaq	internal(%rip), %rdi	/* internal */\n\
  call	pre_clone\n\
  test	 %al, %al\n\
  jnz	.continue\n\
  addq	$80, %rsp\n\
  jmp	.leave\n\
\n\
.continue:\n\
  addq	$16, %rsp\n\
  cmpb	$2, %al			/* replay & no syscall */\n\
  je	.post\n\
  movq	-48(%rbp), %r8		/* tp */\n\
  movq	-40(%rbp), %r10		/* ctid */\n\
  movq	-32(%rbp), %rdx		/* ptid */\n\
  movq	-24(%rbp), %rsi		/* cstack */\n\
  movq	-16(%rbp), %rdi		/* flags */\n\
\n\
  subq	$16, %rsi\n\
  movq	8(%rbp), %rax		/* return address */\n\
  movq	%rax, 8(%rsi)		/* push the return address on the new stack */\n\
  movq	-64(%rbp), %rax\n\
  movq	%rax, (%rsi)		/* clone */\n\
\n\
  movl	-4(%rbp), %eax		/* nr_clone */\n\
  .cfi_endproc\n\
  syscall\n\
  testq	%rax, %rax\n\
  jz	.child\n\
\n\
  .cfi_startproc\n\
  .cfi_def_cfa_offset 16\n\
  .cfi_offset 6, -16\n\
  .cfi_def_cfa_register 6\n\
.post:\n\
  movq	24(%rbp), %rdi		/* &ret */\n\
  movq	%rax, (%rdi)\n\
  movq	%rax, %rdx		/* ret */\n\
  movq	-64(%rbp), %rsi		/* clone */\n\
  leaq	internal(%rip), %rdi	/* internal */\n\
  call	post_clone\n\
  movq	24(%rbp), %rdi\n\
  movq	%rax, (%rdi)\n\
  addq	$64, %rsp\n\
  movb	$1, %al\n\
.leave:\n\
  leave\n\
  .cfi_def_cfa 7, 8\n\
  ret\n\
\n\
.child:\n\
  movq	%rsp, %rbp\n\
  movq	$0, %rdx		/* ret */\n\
  movq	(%rbp), %rsi		/* clone */\n\
  leaq	internal(%rip), %rdi	/* internal */\n\
  call	post_clone\n\
  addq	$8, %rsp\n\
  movb	$2, %al\n\
  ret\n\
  .cfi_endproc\n\
  .size	ent_syscall, .-ent_syscall\n"
);

#else

static char
ent_syscall (int nr, long a1, long a2, long a3, long a4, long a5, long a6, long *ret)
{
  if (! initialized) return 0;

  char res;
  if (nr == __NR_clone)
    {
      struct clone *clone;
      res = pre_clone (&internal, &clone, a1, a2, a3, a4, a5, a6);
      if (ret)
	{
	  *ret = 1 /* (long) ERI_SYSCALL_NCS (nr, a1, a2, a3, a4, a5, a6) */;
	  post_clone (&internal, clone, a1, a2, a3, a4, a5, a6, *ret);
	}
    }
  else res = syscall (&internal, nr, a1, a2, a3, a4, a5, a6, ret);
  return res;
}

#endif

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
