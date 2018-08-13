#include <limits.h>
#include <asm/unistd.h>

#include "recorder.h"

#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/lock.h"
#include "lib/malloc.h"
#include "lib/printf.h"
#include "lib/list.h"
#include "lib/rbtree.h"

struct sigset
{
  unsigned long val[16];
};

struct ers_thread
{
  unsigned long id;

  int fd;

  ERS_LST_NODE_FIELDS (thread)

  struct sigset oldset;
};

struct atomic_lock
{
  void *mem;

  int lock;
  int fd;

  ERS_RBT_NODE_FIELDS (atomic, struct atomic_lock)
};

struct internal
{
  struct ers_thread *(*get_thread) (void *);
  void (*set_thread) (struct ers_thread *, void *);
  void *get_set_thread_arg;

  char *mbuf;
  size_t mbuf_size;
  struct ers_pool pool;

  const char *path;

  int atomic_lock;
  ERS_RBT_TREE_FIELDS (atomic, struct atomic_lock)

  unsigned long thread_id;
  long active_lock;
  int threads_lock;
  ERS_LST_LIST_FIELDS (thread)
};

#define atomic_less_than(x, a, b) (*(a) < *(b))

ERS_DEFINE_RBTREE (static, atomic, struct internal, struct atomic_lock, void *, atomic_less_than)

ERS_DEFINE_LIST (static, thread, struct internal, struct ers_thread)

inline static struct ers_thread *
get_thread (struct internal *internal)
{
  return internal->get_thread (internal->get_set_thread_arg);
}

inline static void
set_thread (struct internal *internal, struct ers_thread *th)
{
  internal->set_thread (th, internal->get_set_thread_arg);
}

static char
itoc (char i)
{
  ers_assert (i >= 0 && i <= 15);
  return i < 10 ? '0' + i : 'a' + i - 10;
}

static char
ctoi (char c)
{
  ers_assert ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'));
  return c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;
}

static void
phex (char *p, unsigned long v)
{
  char i, s = 1;
  while (s < 8 && v & ~(((unsigned long) 1 << (s * 8)) - 1)) ++s;
  for (i = s * 2 - 1; i >= 0; --i)
    {
      p[(unsigned char) i] = itoc (v % 16);
      v /= 16;
    }
  ers_assert (v == 0);
  p[s * 2] = '\0';
}

static int
open_path (const char *path, const char *name, unsigned long id)
{
  size_t npath = ers_strlen (path);
  int nname = ers_strlen (name);

  size_t s = npath + 1 + nname + 2 * sizeof id + 1; /* path/name$id\0 */
  char *p = (char *) __builtin_alloca (s);

  ers_strcpy (p, path);

  size_t c = npath;
  if (npath == 0 || p[npath - 1] != '/') p[c++] = '/';

  ers_strcpy (p + c, name);
  c += nname;

  phex (p + c, id);

  ers_assert (ers_printf ("%s\n", p) == 0);

  int fd;
  ers_assert (ers_fopen (p, 0, &fd) == 0);
  return fd;
}

static struct ers_thread *
init_thread (struct internal *internal, unsigned long id)
{
  struct ers_thread *th;
  ers_assert (ers_calloc (&internal->pool, sizeof *th, (void **) &th) == 0);

  ers_assert (ers_printf ("init_thread %lx\n", th) == 0);

  th->id = id;
  th->fd = open_path (internal->path, "thread-", th->id);

  ers_lock (&internal->threads_lock);
  thread_append (internal, th);
  ers_unlock (&internal->threads_lock);
  return th;
}

static void
fini_thread (struct internal *internal, struct ers_thread *th)
{
  ers_lock (&internal->threads_lock);
  thread_remove (th);
  ers_unlock (&internal->threads_lock);

  ers_assert (ers_printf ("fini_thread %lx\n", th) == 0);
  ers_assert (ers_fclose (th->fd) == 0);
  ers_assert (ers_free (&internal->pool, th) == 0);
}

#define S_IRWXU	0700

static void
init_process (struct internal *internal, const char *path)
{
  ers_assert (ers_printf ("init_process %lx\n", internal) == 0);

  ers_assert (ers_init_pool (&internal->pool,
			     internal->mbuf, internal->mbuf_size) == 0);
  internal->path = path;

  ers_assert (! ERS_SYSCALL_ERROR_P (ERS_SYSCALL (mkdir, internal->path, S_IRWXU)));

  int maps;
  char buf[256];
#if 1
  ers_assert (ers_fopen ("/proc/self/maps", 1, &maps) == 0);
  while (1)
    {
      int l;
      ers_assert (ers_fread (maps, buf, sizeof buf - 1, &l) == 0);
      buf[l] = '\0';
      ers_assert (ers_printf ("%s", buf) == 0);
      if (l != sizeof buf - 1) break;
    }
  ers_assert (ers_fclose (maps) == 0);
#endif

  ers_assert (ers_fopen ("/proc/self/maps", 1, &maps) == 0);

  unsigned long s = 0, e = 0;
  char x = 0, n = 0;
  int p = 0;
  while (1)
    {
      int l;
      ers_assert (ers_fread (maps, buf, sizeof buf, &l) == 0);

      int i;
      for (i = 0; i < l; ++i)
	if (p == 0)
	  {
	    if (buf[i] == '-') p = 1;
	    else s = (s << 4) + ctoi (buf[i]);
	  }
	else if (p == 1)
	  {
	    if (buf[i] == ' ') p = 2;
	    else e = (e << 4) + ctoi (buf[i]);
	  }
	else if (p == 2)
	  {
	    if (n < 3)
	      {
		x |= (buf[i] != '-') << n;
		++n;
	      }
	    else
	      {
		if (buf[i] != 'p')
		  ers_assert (ers_printf ("warning: non private segment\n") == 0);
		/* XXX ers_assert (buf[i] == 'p'); */
		p = 3;
	      }
	  }
	else if (p == 3 && buf[i] == '\n')
	  {
	    char v = i >= 6
		     && (ers_strncmp (buf + i - 6, "[vdso]", 6) == 0
			 || ers_strncmp (buf + i - 6, "[vvar]", 6) == 0);

	    ers_assert (ers_printf ("%lx-%lx %x %u\n", s, e, x, v) == 0);

	    /* TODO */
	    p = 0;
	    s = e = 0;
	    x = n = 0;
	  }

      if (l != sizeof buf) break;
    }
  ers_assert (ers_fclose (maps) == 0);

  ERS_LST_INIT_LIST (thread, internal);

  set_thread (internal, init_thread (internal, internal->thread_id++));
}

#define SIG_SETMASK	2

static void
block_signals (struct sigset *oldset)
{
  struct sigset set;
  ers_memset (&set, 0xff, sizeof set);
  ers_assert (! ERS_SYSCALL_ERROR_P (ERS_SYSCALL (rt_sigprocmask, SIG_SETMASK, &set, oldset, 8)));
}

static void
restore_signals (const struct sigset *oldset)
{
  ers_assert (! ERS_SYSCALL_ERROR_P (ERS_SYSCALL (rt_sigprocmask, SIG_SETMASK, oldset, 0, 8)));
}

static char
acquire_active_lock (struct internal *internal, long v)
{
  struct sigset oldset;
  block_signals (&oldset);
  if (__atomic_add_fetch (&internal->active_lock, v, __ATOMIC_ACQUIRE) > 0)
    {
      ers_memcpy (&get_thread (internal)->oldset, &oldset, sizeof oldset);
      return 1;
    }
  restore_signals (&oldset);
  return 0;
}

static void
release_active_lock (struct internal *internal, long v, char exit)
{
  __atomic_sub_fetch (&internal->active_lock, v, __ATOMIC_RELEASE);
  if (! exit) restore_signals (&get_thread (internal)->oldset);
}

struct child
{
  unsigned long id;
  struct sigset oldset;
};

static char __attribute__ ((used))
pre_syscall (struct internal *internal, struct child **childp,
	     int nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
  ers_assert (ers_printf ("pre_syscall %u\n", nr) == 0);
  if (! acquire_active_lock (internal, nr == __NR_clone ? 2 : 1)) return 0;
  struct ers_thread *th = get_thread (internal);

  if (nr == __NR_clone)
    {
      ers_assert (ers_malloc (&internal->pool, sizeof **childp, (void **) childp) == 0);
      (*childp)->id = __atomic_fetch_add (&internal->thread_id, 1, __ATOMIC_RELAXED);
      ers_memcpy (&(*childp)->oldset, &th->oldset, sizeof th->oldset);
    }
  else if (nr == __NR_exit || nr == __NR_exit_group)
    {
      char grp = th->id == 0 /* main thread */
		 || nr == __NR_exit_group;
      if (grp)
	{
	  unsigned long exp = 1;
	  while (! __atomic_compare_exchange_n (&internal->active_lock, &exp,
						LONG_MIN + 1, 1,
						__ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
	    exp = 1;

	  struct ers_thread *t, *nt;
	  ERS_LST_FOREACH_SAFE (thread, internal, t, nt) fini_thread (internal, t);

	  struct atomic_lock *l, *nl;
	  ERS_RBT_FOREACH_SAFE (atomic, internal, l, nl)
	    {
	      ers_assert (ers_printf ("remove atomic lock %lx\n", l) == 0);
	      ers_assert (ers_fclose (l->fd) == 0);
	      atomic_remove (internal, l);
	      ers_assert (ers_free (&internal->pool, l) == 0);
	    }

	  ers_assert (ers_printf ("used %lu\n", internal->pool.used) == 0);
	  ers_assert (internal->pool.used == 0);
	}
      else fini_thread (internal, th);
    }

  /* TODO */

  if (nr != __NR_clone)
    release_active_lock (internal, 1, nr == __NR_exit || nr == __NR_exit_group);
  return 1;
}

static void __attribute__ ((used))
post_syscall (struct internal *internal, struct child *child,
	      int nr, long a1, long a2, long a3, long a4, long a5, long a6, long ret)
{
  ers_assert (ers_printf ("post_syscall %u\n", nr) == 0);
  if (nr != __NR_clone && ! acquire_active_lock (internal, 1)) return;

  long rel = 1;
  if (nr == __NR_clone)
    {
      if (ERS_SYSCALL_ERROR_P (ret))
	{
	  rel = 2;
	  ers_printf ("!!! %lx\n", child);
	  ers_assert (ers_free (&internal->pool, child) == 0);
	}
      else if (ret == 0)
	{
	  struct ers_thread *th = init_thread (internal, child->id);
	  set_thread (internal, th);
	  ers_memcpy (&th->oldset, &child->oldset, sizeof child->oldset);
	  ers_assert (ers_free (&internal->pool, child) == 0);
	}
    }
  /* TODO */

  release_active_lock (internal, rel, 0);
}

static char
atomic_lock (struct internal *internal, void *mem)
{
  ers_assert (ers_printf ("atomic_lock %lx\n", mem) == 0);
  if (! acquire_active_lock (internal, 1)) return 0;

  struct atomic_lock *lock = atomic_get (internal, &mem, ERS_RBT_EQ);
  if (! lock)
    {
      ers_assert (ers_calloc (&internal->pool, sizeof *lock, (void **) &lock) == 0);
      lock->mem = mem;
      atomic_insert (internal, lock);
    }
  ers_unlock (&internal->atomic_lock);

  ers_lock (&lock->lock);
  if (lock->fd == 0)
    lock->fd = open_path (internal->path, "atomic-", (unsigned long) mem);
  ers_unlock (&lock->lock);
  return 1;
}

static void
atomic_unlock (struct internal *internal, void *mem, int mo)
{
  ers_assert (ers_printf ("atomic_unlock %lx %u\n", mem, mo) == 0);

  ers_lock (&internal->atomic_lock);
  struct atomic_lock *lock = atomic_get (internal, &mem, ERS_RBT_EQ);
  ers_unlock (&internal->atomic_lock);

  ers_assert (lock);
  release_active_lock (internal, 1, 0);
}

static char
atomic_barrier (struct internal *internal, int mo)
{
  ers_assert (ers_printf ("atomic_barrier %u\n", mo) == 0);
  if (! acquire_active_lock (internal, 1)) return 0;
  release_active_lock (internal, 1, 0);
  return 1;
}

static struct internal internal;
static char mbuf[64 * 1024 * 1024];
static char initialized;

static void
rec_init_process (const char *path,
		  struct ers_thread *(*get) (void *),
		  void (*set) (struct ers_thread *, void *),
		  void *arg)
{
  internal.get_thread = get;
  internal.set_thread = set;
  internal.get_set_thread_arg = arg;

  internal.mbuf = mbuf;
  internal.mbuf_size = sizeof mbuf;

  init_process (&internal, path);
  initialized = 1;
}

#if 1
/* static */ char rec_syscall (int nr, long a1, long a2, long a3, long a4,
			       long a5, long a6, long *ret);

asm ("  .text\n\
  .type  rec_syscall, @function\n\
rec_syscall:\n\
  .cfi_startproc\n\
  pushq  %rbp\n\
  .cfi_def_cfa_offset 16\n\
  .cfi_offset 6, -16\n\
  movq  %rsp, %rbp\n\
  .cfi_def_cfa_register 6\n\
  movb  initialized(%rip), %al\n\
  testb  %al, %al\n\
  jz  .leave\n\
  subq  $56, %rsp\n\
  movl  %edi, -4(%rbp)		/* nr */\n\
  movq  %rsi, -16(%rbp)		/* a1 */\n\
  movq  %rdx, -24(%rbp)		/* a2 */\n\
  movq  %rcx, -32(%rbp)		/* a3 */\n\
  movq  %r8, -40(%rbp)		/* a4 */\n\
  movq  %r9, -48(%rbp)		/* a5 */\n\
  pushq  16(%rbp)		/* a6 */\n\
  pushq  -48(%rbp)		/* a5 */\n\
  pushq  -40(%rbp)		/* a4 */\n\
  movq  -32(%rbp), %r9		/* a3 */\n\
  movq  -24(%rbp), %r8		/* a2 */\n\
  movq  -16(%rbp), %rcx		/* a1 */\n\
  movl  -4(%rbp), %edx		/* nr */\n\
  leaq  -56(%rbp), %rsi		/* &child */\n\
  leaq  internal(%rip), %rdi	/* internal */\n\
  call  pre_syscall\n\
  addq  $24, %rsp\n\
  testb  %al, %al\n\
  jz  .leave\n\
  movq  16(%rbp), %r9		/* a6 */\n\
  movq  -48(%rbp), %r8		/* a5 */\n\
  movq  -40(%rbp), %r10		/* a4 */\n\
  movq  -32(%rbp), %rdx		/* a3 */\n\
  movq  -24(%rbp), %rsi		/* a2 */\n\
  movq  -16(%rbp), %rdi		/* a1 */\n\
  cmpl  $"ERS_STRINGIFY (__NR_clone)", -4(%rbp)\n\
  je  .clone\n\
  movl  -4(%rbp), %eax		/* nr */\n\
  syscall\n\
  jmp  .post\n\
.clone:\n\
  subq  $80, %rsi\n\
  movq  8(%rbp), %rax		/* return address */\n\
  movq  %rax, 72(%rsi)		/* push the return address on the new stack */\n\
  movq  -56(%rbp), %rax\n\
  movq  %rax, 56(%rsi)		/* child */\n\
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
  movq  16(%rbp), %rax\n\
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
.post:\n\
  movq  24(%rbp), %rdi\n\
  movq  %rax, (%rdi)\n\
  subq  $8, %rsp\n\
  pushq  %rax			/* ret */\n\
  pushq  16(%rbp)		/* a6 */\n\
  pushq  -48(%rbp)		/* a5 */\n\
  pushq  -40(%rbp)		/* a4 */\n\
  movq  -32(%rbp), %r9		/* a3 */\n\
  movq  -24(%rbp), %r8		/* a2 */\n\
  movq  -16(%rbp), %rcx		/* a1 */\n\
  movl  -4(%rbp), %edx		/* nr */\n\
  movq  -56(%rbp), %rsi		/* child */\n\
  leaq  internal(%rip), %rdi	/* internal */\n\
  call  post_syscall\n\
  addq  $96, %rsp\n\
  movb  $1, %al\n\
.leave:\n\
  leave\n\
  .cfi_def_cfa 7, 8\n\
  ret\n\
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
  movq  56(%rbp), %rsi		/* child */\n\
  leaq  internal(%rip), %rdi	/* internal */\n\
  call  post_syscall\n\
  addq  $104, %rsp\n\
  movb  $2, %al\n\
  ret\n\
  .cfi_endproc\n\
  .size rec_syscall, .-rec_syscall\n"
);

#else

#define ERS_SYSCALL_NCS(nr, ...) \
  _SYSCALL_NR (nr, _SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

static char
rec_syscall (int nr, long a1, long a2, long a3, long a4, long a5, long a6, long *ret)
{
  if (! initialized) return 0;

  char res;
  void *child;
  res = pre_syscall (&internal, &child, nr, a1, a2, a3, a4, a5, a6);
  if (ret)
    {
      *ret = 1 /* (long) ERS_SYSCALL_NCS (nr, a1, a2, a3, a4, a5, a6) */;
      post_syscall (&internal, child, nr, a1, a2, a3, a4, a5, a6, *ret);
    }
  return res;
}

#endif

static char
rec_atomic_lock (void *mem)
{
  return initialized && atomic_lock (&internal, mem);
}

static void
rec_atomic_unlock (void *mem, int mo)
{
  atomic_unlock (&internal, mem, mo);
}

static char
rec_atomic_barrier (int mo)
{
  return initialized && atomic_barrier (&internal, mo);
}

static struct ers_recorder recorder = {

  rec_init_process,
  rec_syscall,
  rec_atomic_lock,
  rec_atomic_unlock,
  rec_atomic_barrier
};

__attribute__ ((visibility ("default"))) struct ers_recorder *
ers_get_recorder (void)
{
  return &recorder;
}
