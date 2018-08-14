#include <limits.h>
#include <asm/unistd.h>

#include "recorder.h"
#include "common.h"

#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/malloc.h"
#include "lib/printf.h"
#include "lib/list.h"
#include "lib/rbtree.h"

struct lock
{
  int lock;
  int fd;
};

#define init_lock (lock, fd) \
  do { struct lock *_l = lock; _l->lock = 0; _l->fd = fd; } while (0)

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
  do_lock (&lock->lock);
}

static void
lunlock (struct lock *lock)
{
  do_unlock (&lock->lock);
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
    lunlock (&__m->lock);				\
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
    lunlock (&__m->lock);				\
    __ex;						\
  })

struct sigset
{
  unsigned long val[16];
};

struct ers_thread
{
  unsigned long id;

  int fd;

  ERI_LST_NODE_FIELDS (thread)

  struct sigset old_set;
};

struct atomic_lock
{
  void *mem;

  struct lock lock;
  int fd;

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
  struct ers_thread *(*get_thread) (void *);
  void (*set_thread) (struct ers_thread *, void *);
  void *get_set_thread_arg;

  struct lock pool_lock;
  char *pool_buf;
  size_t pool_buf_size;
  struct eri_pool pool;

  const char *path;

  char replay;

  struct lock atomic_lock;
  ERI_RBT_TREE_FIELDS (atomic, struct atomic_lock)

  ATOMIC_TYPE (unsigned long) thread_id;
  ATOMIC_TYPE (long) active_lock;
  struct lock threads_lock;
  ERI_LST_LIST_FIELDS (thread)

  struct lock sigact_lock;
  ERI_RBT_TREE_FIELDS (sigact, struct sigact_wrap)
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
  lunlock (&internal->pool_lock);
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
  lunlock (&internal->pool_lock);
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
init_thread (struct internal *internal, unsigned long id)
{
  char re = internal->replay;
  struct ers_thread *th = icalloc (internal, id, sizeof *th);

  eri_assert (eri_printf ("init_thread %lx\n", th) == 0);

  th->id = id;
  th->fd = eri_open_path (internal->path, "thread-",
			  ERI_OPEN_WITHID | re << ERI_OPEN_REPLAY,
			  th->id);

  llock (re, th->id, &internal->threads_lock);
  thread_append (internal, th);
  lunlock (&internal->threads_lock);
  return th;
}

static void
fini_thread (struct internal *internal, struct ers_thread *th)
{
  llock (internal->replay, th->id, &internal->threads_lock);
  thread_remove (th);
  lunlock (&internal->threads_lock);

  eri_assert (eri_printf ("fini_thread %lx\n", th) == 0);
  eri_assert (eri_fclose (th->fd) == 0);
  ifree (internal, th->id, th);
}

asm ("  .text\n\
  .type set_context, @function\n\
set_context:\n\
  movq  %rbx, (%rdi)\n\
  movq  %rbp, 8(%rdi)\n\
  movq  %r12, 16(%rdi)\n\
  movq  %r13, 24(%rdi)\n\
  movq  %r14, 32(%rdi)\n\
  movq  %r15, 40(%rdi)\n\
\n\
  movq  %rdi, 48(%rdi)\n\
  movq  %rsi, 56(%rdi)\n\
  movq  %rdx, 64(%rdi)\n\
  movq  %rcx, 72(%rdi)\n\
  movq  %r8, 80(%rdi)\n\
  movq  %r9, 88(%rdi)\n\
\n\
  movq  (%rsp), %rcx\n\
  movq  %rcx, 96(%rdi)		/* %rip */\n\
  leaq  8(%rsp), %rcx\n\
  movq  %rcx, 104(%rdi)		/* %rsp */\n\
\n\
  leaq    112(%rdi), %rcx\n\
  fnstenv (%rcx)\n\
  fldenv  (%rcx)\n\
  stmxcsr 136(%rdi)\n\
\n\
  xorb %al, %al\n\
  ret\n\
  .size set_context, .-set_context\n"
);

/* static */ char set_context (struct eri_context *ctx);

static char
init_context (int init)
{
  struct eri_context ctx;
  if (set_context (&ctx) == 0)
    {
      eri_save_mark (init, ERI_SMARK_INIT_CONTEXT);
      eri_save_init_context (init, &ctx);
      eri_assert (eri_fclose (init) == 0);
      return 0;
    }

  eri_assert (eri_printf ("replay!!!\n") == 0);
  eri_dump_maps ();
  ERI_ASSERT_SYSCALL (munmap, ctx.unmap_start, ctx.unmap_size);
  while (1) continue;
  return 1; /* replay */
}

#define S_IRWXU	0700

struct proc_map_data
{
  int init;
  unsigned long pool_start;
};

static void
proc_map_entry (const struct eri_map_entry *ent, void *data)
{
  if (ent->path
      && (eri_strcmp (ent->path, "[vdso]") == 0
	  || eri_strcmp (ent->path, "[vvar]") == 0
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

  eri_save_mark (d->init, ERI_SMARK_INIT_MAP);
  eri_save_init_map (d->init, start, end, flags);
  if (flags & 1 && ! (flags & 8)) /* readable & ! all zero */
    eri_save_init_map_data (d->init, (const char *) start, end - start);
}

static void
init_process (struct internal *internal, const char *path)
{
  eri_assert (eri_printf ("init_process %lx\n", internal) == 0);

  internal->path = path;

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

  ERI_LST_INIT_LIST (thread, internal);

  internal->replay = init_context (init);

  eri_assert (eri_init_pool (&internal->pool,
			     internal->pool_buf,
			     internal->pool_buf_size) == 0);

  set_thread (internal,
	      init_thread (internal, internal->thread_id.val++));
}

#define SIG_SETMASK	2
#define SIG_SETSIZE	8

static void
block_signals (char replay, struct sigset *old_set)
{
  if (replay) return;

  struct sigset set;
  eri_memset (&set, 0xff, sizeof set);
  ERI_ASSERT_SYSCALL (rt_sigprocmask, SIG_SETMASK, &set, old_set, SIG_SETSIZE);
}

static void
restore_signals (char replay, const struct sigset *old_set)
{
  if (replay) return;
  ERI_ASSERT_SYSCALL (rt_sigprocmask, SIG_SETMASK, old_set, 0, SIG_SETSIZE);
}

static char
acquire_active_lock (struct internal *internal, long v)
{
  char re = internal->replay;

  struct sigset old_set;
  block_signals (re, &old_set);

  do_lock (&internal->active_lock.lock.lock);
  if (++internal->active_lock.val > 0)
    {
      struct ers_thread *th = get_thread (internal);
      /* TODO record order */
      eri_memcpy (&th->old_set, &old_set, sizeof old_set);
      do_unlock (&internal->active_lock.lock.lock);
      return 1;
    }
  do_unlock (&internal->active_lock.lock.lock);
  restore_signals (re, &old_set);
  return 0;
}

static void
release_active_lock (struct internal *internal, long v, char exit)
{
  char re = internal->replay;
  struct ers_thread *th = get_thread (internal);
  ATOMIC_SUB_FETCH (re, th->id, &internal->active_lock, v);
  if (! exit) restore_signals (re, &get_thread (internal)->old_set);
}

static inline char
interruptible (int nr)
{
  return nr != __NR_clone
	 && nr != __NR_exit && nr != __NR_exit_group
	 && nr != __NR_rt_sigaction;
}

struct clone_data
{
  unsigned long child_id;
  struct sigset old_set;
};

struct rt_sigaction_data
{
  void *old_act;
  int old_flags;
};

struct siginfo
{
  /* TODO */
};

struct sigaction
{
  void *act;
  struct sigset mask;
  int flags;
  void (*restorer) (void);
};

static void
ent_sigaction (int sig, struct siginfo *info, void *ucontext);

#define SA_SIGINFO	4

static char __attribute__ ((used))
pre_syscall (struct internal *internal, void **data,
	     int *nr, long *a1, long *a2, long *a3, long *a4, long *a5, long *a6)
{
  eri_assert (eri_printf ("pre_syscall %u\n", *nr) == 0);
  if (! acquire_active_lock (internal, *nr == __NR_clone ? 2 : 1)) return 0;
  char re = internal->replay;
  struct ers_thread *th = get_thread (internal);

  *data = 0;
  if (*nr == __NR_clone)
    {
      *data = imalloc (internal, th->id, sizeof (struct clone_data));
      struct clone_data *d = *data;
      d->child_id = ATOMIC_FETCH_ADD (re, th->id, &internal->thread_id, 1);
      eri_memcpy (&d->old_set, &th->old_set, sizeof th->old_set);
    }
  else if (*nr == __NR_exit || *nr == __NR_exit_group)
    {
      char grp = th->id == 0 /* main thread */
		 || *nr == __NR_exit_group;
      if (grp)
	{
	  unsigned long exp = 1;
	  while (! ATOMIC_COMPARE_EXCHANGE (re, th->id, &internal->active_lock, exp,
					    LONG_MIN + 1))
	    continue;

	  struct ers_thread *t, *nt;
	  ERI_LST_FOREACH_SAFE (thread, internal, t, nt) fini_thread (internal, t);

	  struct atomic_lock *l, *nl;
	  ERI_RBT_FOREACH_SAFE (atomic, internal, l, nl)
	    {
	      eri_assert (eri_printf ("remove atomic lock %lx\n", l) == 0);
	      eri_assert (eri_fclose (l->fd) == 0);
	      atomic_remove (internal, l);
	      ifree (internal, th->id, l);
	    }

	  struct sigact_wrap *w, *nw;
	  ERI_RBT_FOREACH_SAFE (sigact, internal, w, nw)
	    {
	      eri_assert (eri_printf ("remove sigact wrap %lx\n", w) == 0);
	      sigact_remove (internal, w);
	      ifree (internal, th->id, w);
	    }

	  eri_assert (eri_printf ("used %lu\n", internal->pool.used) == 0);
	  eri_assert (eri_fini_pool (&internal->pool) == 0);
	  ERI_ASSERT_SYSCALL (munmap, internal->pool_buf, internal->pool_buf_size);
	  internal->pool_buf = 0;
	  internal->pool_buf_size = 0;
	}
      else
	{
	  fini_thread (internal, th);
	  release_active_lock (internal, 1, 1);
	}
    }
  else if (*nr == __NR_rt_sigaction)
    {
      if (a2 || a3)
	{
	  int sig = (int) *a1;
	  const struct sigaction *act = (const struct sigaction *) *a2;
	  llock (internal->replay, th->id, &internal->sigact_lock);
	  struct sigact_wrap *wrap = sigact_get (internal, &sig, ERI_RBT_EQ);

	  if (a3 && wrap)
	    {
	      *data = imalloc (internal, th->id, sizeof (struct rt_sigaction_data));
	      struct rt_sigaction_data *d = *data;
	      d->old_act = wrap->act;
	      d->old_flags = wrap->flags;
	    }

	  if (act)
	    {
	      if (! wrap)
		{
		  wrap = imalloc (internal, th->id, sizeof *wrap);
		  wrap->sig = sig;
		  sigact_insert (internal, wrap);
		}

	      wrap->act = act->act;
	      wrap->flags = act->flags;

	      struct sigaction *newact = imalloc (internal, th->id, sizeof *newact);
	      newact->act = ent_sigaction;
	      newact->mask = act->mask;
	      newact->flags = act->flags | SA_SIGINFO;
	      newact->restorer = act->restorer;
	      *(struct sigaction **) a2 = newact;
	    }
	}
    }

  /* TODO */

  if (interruptible (*nr))
    release_active_lock (internal, 1, 0);
  return 1;
}

static void __attribute__ ((used))
post_syscall (struct internal *internal, void *data,
	      int nr, long a1, long a2, long a3, long a4, long a5, long a6, long ret)
{
  eri_assert (eri_printf ("post_syscall %u %lu\n", nr, ret) == 0);
  if (interruptible (nr) && ! acquire_active_lock (internal, 1)) return;
  struct ers_thread *th = (nr != __NR_clone || ! ret) ? get_thread (internal) : 0;

  long rel = 1;
  if (nr == __NR_clone)
    {
      struct clone_data *d = data;
      if (ERI_SYSCALL_ERROR_P (ret))
	{
	  rel = 2;
	  ifree (internal, th->id, data);
	}
      else if (ret == 0)
	{
	  set_thread (internal, th = init_thread (internal, d->child_id));
	  eri_memcpy (&th->old_set, &d->old_set, sizeof d->old_set);
	  ifree (internal, th->id, data);
	}
    }
  else if (nr == __NR_rt_sigaction)
    {
      if (a2 || a3) lunlock (&internal->sigact_lock);

      ifree (internal, th->id, (void *) a2);
      if (! ERI_SYSCALL_ERROR_P (ret) && a3 && data)
	{
	  struct sigaction *act = (struct sigaction *) a3;
	  struct rt_sigaction_data *d = data;
	  act->act = d->old_act;
	  act->flags = d->old_flags;
	}
      ifree (internal, th->id, data);
    }
  /* TODO */

  release_active_lock (internal, rel, 0);
}

static void
sigaction (struct internal *internal, int sig, struct siginfo *info, void *ucontext)
{
  eri_assert (eri_printf ("sigaction %u\n", sig) == 0);
  struct ers_thread *th = get_thread (internal);

  struct sigset old_set;
  block_signals (internal->replay, &old_set);
  llock (internal->replay, th->id, &internal->sigact_lock);

  struct sigact_wrap *wrap = sigact_get (internal, &sig, ERI_RBT_EQ);
  eri_assert (wrap);
  void *act = wrap->act;
  int flags = wrap->flags;

  lunlock (&internal->sigact_lock);
  restore_signals (internal->replay, &old_set);

  if (flags & SA_SIGINFO)
    ((void (*) (int, struct siginfo *, void *)) act) (sig, info, ucontext);
  else
    ((void (*) (int)) act) (sig);
}

static char
atomic_lock (struct internal *internal, void *mem)
{
  eri_assert (eri_printf ("atomic_lock %lx\n", mem) == 0);
  if (! acquire_active_lock (internal, 1)) return 0;
  struct ers_thread *th = get_thread (internal);

  struct atomic_lock *lock = atomic_get (internal, &mem, ERI_RBT_EQ);
  if (! lock)
    {
      lock = icalloc (internal, th->id, sizeof *lock);
      lock->mem = mem;
      atomic_insert (internal, lock);
    }
  lunlock (&internal->atomic_lock);

  llock (internal->replay, th->id, &lock->lock);
  if (lock->fd == 0)
    lock->fd = eri_open_path (internal->path, "atomic-",
			      ERI_OPEN_WITHID | internal->replay << ERI_OPEN_REPLAY,
			      (unsigned long) mem);
  lunlock (&lock->lock);
  return 1;
}

static void
atomic_unlock (struct internal *internal, void *mem, int mo)
{
  eri_assert (eri_printf ("atomic_unlock %lx %u\n", mem, mo) == 0);
  struct ers_thread *th = get_thread (internal);

  llock (internal->replay, th->id, &internal->atomic_lock);
  struct atomic_lock *lock = atomic_get (internal, &mem, ERI_RBT_EQ);
  lunlock (&internal->atomic_lock);

  eri_assert (lock);
  release_active_lock (internal, 1, 0);
}

static char
atomic_barrier (struct internal *internal, int mo)
{
  eri_assert (eri_printf ("atomic_barrier %u\n", mo) == 0);
  if (! acquire_active_lock (internal, 1)) return 0;
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
  internal.get_thread = get;
  internal.set_thread = set;
  internal.get_set_thread_arg = arg;

  init_process (&internal, path);
  initialized = 1;
}

#if 1
/* static */ char ent_syscall (int nr, long a1, long a2, long a3, long a4,
			       long a5, long a6, long *ret);

asm ("  .text\n\
  .type  ent_syscall, @function\n\
ent_syscall:\n\
  .cfi_startproc\n\
  pushq  %rbp\n\
  .cfi_def_cfa_offset 16\n\
  .cfi_offset 6, -16\n\
  movq  %rsp, %rbp\n\
  .cfi_def_cfa_register 6\n\
  movb  initialized(%rip), %al\n\
  testb  %al, %al\n\
  jz  .leave\n\
\n\
  subq  $72, %rsp\n\
  movl  %edi, -4(%rbp)		/* nr */\n\
  movq  %rsi, -16(%rbp)		/* a1 */\n\
  movq  %rdx, -24(%rbp)		/* a2 */\n\
  movq  %rcx, -32(%rbp)		/* a3 */\n\
  movq  %r8, -40(%rbp)		/* a4 */\n\
  movq  %r9, -48(%rbp)		/* a5 */\n\
  movq  16(%rbp), %rax\n\
  movq  %rax, -56(%rbp)		/* a6 */\n\
\n\
  leaq  -56(%rbp), %rax\n\
  pushq %rax			/* &a6 */\n\
  leaq  -48(%rbp), %rax\n\
  pushq %rax			/* &a5 */\n\
  leaq  -40(%rbp), %rax\n\
  pushq %rax			/* &a4 */\n\
  leaq  -32(%rbp), %r9		/* &a3 */\n\
  leaq  -24(%rbp), %r8		/* &a2 */\n\
  leaq  -16(%rbp), %rcx		/* &a1 */\n\
  leaq  -4(%rbp), %rdx		/* &nr */\n\
  leaq  -64(%rbp), %rsi		/* &data */\n\
  leaq  internal(%rip), %rdi	/* internal */\n\
  call  pre_syscall\n\
  addq  $24, %rsp\n\
  testb  %al, %al\n\
  jz  .leave\n\
\n\
  movq  -56(%rbp), %r9		/* a6 */\n\
  movq  -48(%rbp), %r8		/* a5 */\n\
  movq  -40(%rbp), %r10		/* a4 */\n\
  movq  -32(%rbp), %rdx		/* a3 */\n\
  movq  -24(%rbp), %rsi		/* a2 */\n\
  movq  -16(%rbp), %rdi		/* a1 */\n\
  cmpl  $"ERI_STRINGIFY (__NR_clone)", -4(%rbp)\n\
  je  .clone\n\
  movl  -4(%rbp), %eax		/* nr */\n\
  syscall\n\
  jmp  .post\n\
\n\
.clone:\n\
  subq  $80, %rsi\n\
  movq  8(%rbp), %rax		/* return address */\n\
  movq  %rax, 72(%rsi)		/* push the return address on the new stack */\n\
  movq  -64(%rbp), %rax\n\
  movq  %rax, 56(%rsi)		/* data */\n\
  movl  -4(%rbp), %eax\n\
  movl  %eax, 52(%rsi)		/* nr */\n\
  movq  -16(%rbp), %rax\n\
  movq  %rax, 40(%rsi)		/* a1 */\n\
  movq  -24(%rbp), %rax\n\
  movq  %rax, 32(%rsi)		/* a2 */\n\
  movq  -32(%rbp), %rax\n\
  movq  %rax, 24(%rsi)		/* a3 */\n\
  movq  -40(%rbp), %rax\n\
  movq  %rax, 16(%rsi)		/* a4 */\n\
  movq  -48(%rbp), %rax\n\
  movq  %rax, 8(%rsi)		/* a5 */\n\
  movq  -56(%rbp), %rax\n\
  movq  %rax, (%rsi)		/* a6 */\n\
  movl  -4(%rbp), %eax		/* nr */\n\
  .cfi_endproc\n\
  syscall\n\
  testq  %rax, %rax\n\
  jz  .child\n\
  .cfi_startproc\n\
  .cfi_def_cfa_offset 16\n\
  .cfi_offset 6, -16\n\
  .cfi_def_cfa_register 6\n\
\n\
.post:\n\
  movq  24(%rbp), %rdi\n\
  movq  %rax, (%rdi)\n\
  subq  $8, %rsp\n\
  pushq  %rax			/* ret */\n\
  pushq  -56(%rbp)		/* a6 */\n\
  pushq  -48(%rbp)		/* a5 */\n\
  pushq  -40(%rbp)		/* a4 */\n\
  movq  -32(%rbp), %r9		/* a3 */\n\
  movq  -24(%rbp), %r8		/* a2 */\n\
  movq  -16(%rbp), %rcx		/* a1 */\n\
  movl  -4(%rbp), %edx		/* nr */\n\
  movq  -64(%rbp), %rsi		/* data */\n\
  leaq  internal(%rip), %rdi	/* internal */\n\
  call  post_syscall\n\
  addq  $112, %rsp\n\
  movb  $1, %al\n\
.leave:\n\
  leave\n\
  .cfi_def_cfa 7, 8\n\
  ret\n\
\n\
.child:\n\
  movq  %rsp, %rbp\n\
  subq  $8, %rsp\n\
  movq  $0, (%rsp)		/* ret */\n\
  pushq  (%rbp)			/* a6 */\n\
  pushq  8(%rbp)		/* a5 */\n\
  pushq  16(%rbp)		/* a4 */\n\
  movq  24(%rbp), %r9		/* a3 */\n\
  movq  32(%rbp), %r9		/* a2 */\n\
  movq  40(%rbp), %rcx		/* a1 */\n\
  movl  52(%rbp), %edx		/* nr */\n\
  movq  56(%rbp), %rsi		/* data */\n\
  leaq  internal(%rip), %rdi	/* internal */\n\
  call  post_syscall\n\
  addq  $104, %rsp\n\
  movb  $2, %al\n\
  ret\n\
  .cfi_endproc\n\
  .size ent_syscall, .-ent_syscall\n"
);

#else

#define ERI_SYSCALL_NCS(nr, ...) \
  _SYSCALL_NR (nr, _SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

static char
ent_syscall (int nr, long a1, long a2, long a3, long a4, long a5, long a6, long *ret)
{
  if (! initialized) return 0;

  char res;
  void *data;
  res = pre_syscall (&internal, &data, nr, a1, a2, a3, a4, a5, a6);
  if (ret)
    {
      *ret = 1 /* (long) ERI_SYSCALL_NCS (nr, a1, a2, a3, a4, a5, a6) */;
      post_syscall (&internal, data, nr, a1, a2, a3, a4, a5, a6, *ret);
    }
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
