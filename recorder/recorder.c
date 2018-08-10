#include <fcntl.h>
#include <asm/unistd.h>

#include "recorder.h"

#include "lib/util.h"
#include "lib/syscall.h"
#include "lib/lock.h"
#include "lib/malloc.h"
#include "lib/printf.h"
#include "lib/rbtree.h"

struct ers_thread
{
  unsigned long cid;

  unsigned long *id;
  int nid;

  int fd;
};

struct atomic_lock
{
  void *mem;
  size_t size;

  ERS_RBT_NODE_FIELDS (atomic, struct atomic_lock)
};

struct atomic_locks
{
  ERS_RBT_TREE_FIELDS (atomic, struct atomic_lock)
  int lock;
};

ERS_DEFINE_RBTREE (static, atomic, struct atomic_locks, struct atomic_lock, void, ers_less_than)

struct ers_internal
{
  char buf[64 * 1024 * 1024];
  struct ers_pool pool;

  const char *path;
  size_t npath;

  struct atomic_locks atomic_locks;
};

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

static struct ers_thread *
init_thread (struct ers_internal *internal, struct ers_thread *parent)
{
  struct ers_thread *th;
  ers_assert (ers_calloc (&internal->pool, sizeof *th, (void **) &th) == 0);

  ers_assert (ers_printf ("init_thread %lx %lx\n", th, parent) == 0);

  if (parent)
    {
      th->nid = parent->nid + 1;
      ers_assert (ers_malloc (&internal->pool,
			      sizeof *th->id * th->nid, (void **) &th->id) == 0);
      ers_memcpy (th->id, parent->id, sizeof *th->id * (th->nid - 1));
      th->id[th->nid - 1] = parent->cid++;
    }

  size_t npath = internal->npath;
  const char *name = "thread";
  int nname = ers_strlen ("thread");

  size_t s = npath + 1 + nname + th->nid * (2 * sizeof *th->id + 1) + 1;
  char *p = (char *) __builtin_alloca (s);

  ers_strcpy (p, internal->path);

  size_t c = npath;
  if (npath == 0 || p[npath - 1] != '/') p[c++] = '/';

  ers_strcpy (p + c, name);
  c += nname;

  int i, j;
  for (i = 0; i < th->nid; ++i)
    {
      p[c++] = '-';
      unsigned long iid = th->id[i];
      char s = 1;
      while (s < 8 && iid & ~((1 << (s * 8)) - 1)) ++s;
      for (j = s * 2 - 1; j >= 0; --j)
	{
	  p[c + j] = itoc (iid % 16);
	  iid /= 16;
	}
      ers_assert (iid == 0);
      c += s * 2;
    }
  p[c] = '\0';

  ers_assert (ers_printf ("%s\n", p) == 0);
  ers_assert (ers_fopen (p, 0, &th->fd) == 0);

  return th;
}

static void
fini_thread (struct ers_internal *internal, struct ers_thread *th)
{
  ers_assert (ers_printf ("fini_thread %lx\n", th) == 0);
  ers_assert (ers_fclose (th->fd) == 0);
  ers_assert (ers_free (&internal->pool, th->id) == 0);
  ers_assert (ers_free (&internal->pool, th) == 0);
}

static struct ers_thread *
init_process (struct ers_recorder *recorder, const char *path)
{
  ers_assert (ers_printf ("internal %u\n", __builtin_offsetof (struct ers_recorder, internal)) == 0);
  ers_assert (ers_printf ("syscall %u\n", __builtin_offsetof (struct ers_recorder, syscall)) == 0);

  struct ers_internal *internal = recorder->internal;
  ers_assert (ers_init_pool (&internal->pool,
			     internal->buf, sizeof internal->buf) == 0);
  internal->path = path;
  internal->npath = ers_strlen (internal->path);

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
		ers_assert (buf[i] == 'p');
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

  recorder->initialized = 1;
  struct ers_thread *th = init_thread (internal, NULL);

  /* TODO */
  return th;
}

static void __attribute__ ((used))
pre_syscall (struct ers_internal *internal, struct ers_thread *th, void *args,
	     long nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
  ers_assert (ers_printf ("pre_syscall %lx %lx %lu\n", th, args, nr) == 0);
  if (nr == __NR_clone)
    {
      struct ers_thread **nthp = args;
      *nthp = init_thread (internal, th);
    }
  /* TODO */
}

static void __attribute__ ((used))
post_syscall (struct ers_internal *internal, struct ers_thread *th, void *args,
	      long nr, long a1, long a2, long a3, long a4, long a5, long a6, long res)
{
  ers_assert (ers_printf ("post_syscall %lx %lx\n", th, args) == 0);
  if (nr == __NR_clone && ERS_SYSCALL_ERROR_P (res))
    {
      struct ers_thread **nthp = args;
      fini_thread (internal, *nthp);
      *nthp = 0;
    }
  /* TODO */
}

#if 1
/* static */ long syscall (struct ers_internal *internal, struct ers_thread *th,
			   void *args, int nr, long a1, long a2, long a3, long a4,
			   long a5, long a6);

asm ("  .text\n\
  .type  syscall, @function\n\
syscall:\n\
  .cfi_startproc\n\
  pushq  %rbp\n\
  .cfi_def_cfa_offset 16\n\
  .cfi_offset 6, -16\n\
  movq  %rsp, %rbp\n\
  .cfi_def_cfa_register 6\n\
  subq  $64, %rsp\n\
  movq  %rdi, -24(%rbp)		/* internal */\n\
  movq  %rsi, -32(%rbp)		/* th */\n\
  movq  %rdx, -40(%rbp)		/* args */\n\
  movl  %ecx, -44(%rbp)		/* nr */\n\
  movq  %r8, -56(%rbp)		/* a1 */\n\
  movq  %r9, -64(%rbp)		/* a2 */\n\
  pushq  40(%rbp)		/* a6 */\n\
  pushq  32(%rbp)		/* a5 */\n\
  pushq  24(%rbp)		/* a4 */\n\
  pushq  16(%rbp)		/* a3 */\n\
  movq  -64(%rbp), %r9		/* a2 */\n\
  movq  -56(%rbp), %r8		/* a1 */\n\
  movl  -44(%rbp), %ecx		/* nr */\n\
  movq  -40(%rbp), %rdx		/* args */\n\
  movq  -32(%rbp), %rsi		/* th */\n\
  movq  -24(%rbp), %rdi		/* internal */\n\
  call  pre_syscall\n\
  addq  $32, %rsp\n\
  movq  40(%rbp), %r9		/* a6 */\n\
  movq  32(%rbp), %r8		/* a5 */\n\
  movq  24(%rbp), %r10		/* a4 */\n\
  movq  16(%rbp), %rdx		/* a3 */\n\
  movq  -64(%rbp), %rsi		/* a2 */\n\
  movq  -56(%rbp), %rdi		/* a1 */\n\
  movl  -44(%rbp), %eax		/* nr */\n\
  cmpl  $"ERS_STRINGIFY (__NR_clone)", -44(%rbp);\n\
  je  .clone\n\
  syscall\n\
  movq  %rax, -8(%rbp)		/* res */\n\
  jmp  .post\n\
.clone:\n\
  subq  $8, %rsi\n\
  movq  8(%rbp), %r11		/* return address */\n\
  movq  %r11, (%rsi)		/* push the return address on the new stack */\n\
  .cfi_endproc\n\
  syscall\n\
  testq  %rax, %rax\n\
  jz  .child\n\
  .cfi_startproc\n\
  .cfi_def_cfa_offset 16\n\
  .cfi_offset 6, -16\n\
  .cfi_def_cfa_register 6\n\
  movq  %rax, -8(%rbp)		/* res */\n\
  jmp  .post\n\
.child:\n\
  ret\n\
.post:\n\
  subq  $8, %rsp\n\
  pushq  -8(%rbp)		/* res */\n\
  pushq  40(%rbp)		/* a6 */\n\
  pushq  32(%rbp)		/* a5 */\n\
  pushq  24(%rbp)		/* a4 */\n\
  pushq  16(%rbp)		/* a3 */\n\
  movq  -64(%rbp), %r9		/* a2 */\n\
  movq  -56(%rbp), %r8		/* a1 */\n\
  movl  -44(%rbp), %ecx		/* nr */\n\
  movq  -40(%rbp), %rdx		/* args */\n\
  movq  -32(%rbp), %rsi		/* th */\n\
  movq  -24(%rbp), %rdi		/* internal */\n\
  call  post_syscall\n\
  addq  $48, %rsp\n\
  movq  -8(%rbp), %rax\n\
  leave\n\
  .cfi_def_cfa 7, 8\n\
  ret\n\
  .cfi_endproc\n\
  .size syscall, .-syscall\n"
);

#else

#define ERS_SYSCALL_NCS(nr, ...) \
  _SYSCALL_NR (nr, _SYSCALL_NARGS (0, ##__VA_ARGS__), ##__VA_ARGS__)

static long
syscall (struct ers_internal *internal, struct ers_thread *th, void *args,
	 int nr, long a1, long a2, long a3, long a4, long a5, long a6)
{
  pre_syscall (internal, th, args, nr, a1, a2, a3, a4, a5, a6);
  long res = 1 /* (long) ERS_SYSCALL_NCS (nr, a1, a2, a3, a4, a5, a6) */;
  post_syscall (internal, th, args, nr, a1, a2, a3, a4, a5, a6, res);
  return res;
}

#endif

static void
atomic_lock (struct ers_internal *internal, struct ers_thread* th, void *mem, int size, int mo)
{
  struct atomic_locks *locks = &internal->atomic_locks;
  ers_lock (&locks->lock);

  ers_assert (ers_printf ("atomic_lock %lx %lx %u %u\n", th, mem, size, mo) == 0);
  struct atomic_lock *lock = atomic_get (locks, mem, ERS_RBT_EQ | ERS_RBT_LT);
  if (! lock || (char *) lock->mem + lock->size <= (char *) mem)
    {
      ers_assert (ers_calloc (&internal->pool, sizeof *lock, (void **) &lock) == 0);
      lock->mem = mem;
      lock->size = size;
      atomic_insert (locks, lock);
    }
  else ers_assert (lock->mem == mem && lock->size == size);
}

static void
atomic_unlock (struct ers_internal *internal, struct ers_thread *th, void *mem)
{
  ers_assert (ers_printf ("atomic_unlock %lx\n", mem) == 0);
  ers_unlock (&internal->atomic_locks.lock);
}

static void
atomic_barrier (struct ers_internal *internal, struct ers_thread *th, int mo)
{
  ers_assert (ers_printf ("atomic_barrier %lx %u\n", th, mo) == 0);
}

static struct ers_internal internal;

static struct ers_recorder recorder = {

  0,
  &internal,

  init_process,
  syscall,
  atomic_lock,
  atomic_unlock,
  atomic_barrier
};

__attribute__ ((visibility ("default"))) struct ers_recorder *
ers_get_recorder (void)
{
  return &recorder;
}
