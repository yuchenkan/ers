#include <asm/unistd.h>

#include "recorder.h"
#include "thread.h"

#include "lib/util.h"
#include "lib/env.h"
#include "lib/lock.h"
#include "lib/malloc.h"
#include "lib/printf.h"
#include "lib/rbtree.h"

struct atomic_lock
{
  void *mem;
  size_t size;

  ERS_RBT_NODE_FIELDS (struct atomic_lock)
};

struct atomic_locks
{
  ERS_RBT_TREE_FIELDS (struct atomic_lock)
  int lock;
};

ERS_DEFINE_RBTREE (static, atomic, struct atomic_locks, struct atomic_lock, void, ers_less_than)

struct ers_internal
{
  char buf[64 * 1024 * 1024];
  struct ers_pool pool;

  const char *path;

  struct atomic_locks atomic_locks;
};

static void
ers_init_process (struct ers_recorder *self)
{
  ers_assert (ers_init_pool (&self->internal->pool, self->internal->buf, sizeof self->internal->buf) == 0);
  ers_assert (ers_get_env ("ERS_RECORD_PATH", &self->internal->path) == 0);

  self->initialized = 1;
}

static struct ers_thread *
ers_init_thread (struct ers_recorder *self)
{
  struct ers_thread *th;
  ers_assert (ers_calloc (&self->internal->pool, sizeof *th, (void **) &th) == 0);
  th->recorder = self;
  /* th->external = (long) th + 1234; */
  ers_printf ("init thread %lx\n", th);
  return th;
}

static void
ers_fini_thread (struct ers_thread *th)
{
  ers_printf ("fini thread %lx\n", th);
  ers_assert (ers_free (&th->recorder->internal->pool, th) == 0);
}

static void __attribute__ ((used))
ers_pre_syscall (struct ers_thread *th, struct ers_thread *new_th, long nr,
		 long a1, long a2, long a3, long a4, long a5, long a6)
{
  ers_printf ("ers_pre_syscall %lx %lx\n", th, new_th);
  /* TODO */
}

static void __attribute__ ((used))
ers_post_syscall (struct ers_thread *th, struct ers_thread *new_th, long nr,
		  long a1, long a2, long a3, long a4, long a5, long a6, long res)
{
  ers_printf ("ers_post_syscall %lx %lx\n", th, new_th);
  /* TODO */
}

/* static */ long ers_syscall (struct ers_thread *th, struct ers_thread *new_th,
			       int nr, long a1, long a2, long a3, long a4,
			       long a5, long a6);

#if 1
asm ("  .text\n\
  .type  ers_syscall, @function\n\
ers_syscall:\n\
  .cfi_startproc\n\
  pushq  %rbp\n\
  .cfi_def_cfa_offset 16\n\
  .cfi_offset 6, -16\n\
  movq  %rsp, %rbp\n\
  .cfi_def_cfa_register 6\n\
  subq  $64, %rsp\n\
  movq  %rdi, -24(%rbp)		/* th */\n\
  movq  %rsi, -32(%rbp)		/* new_th */\n\
  movl  %edx, -36(%rbp)		/* nr */\n\
  movq  %rcx, -48(%rbp)		/* a1 */\n\
  movq  %r8, -56(%rbp)		/* a2 */\n\
  movq  %r9, -64(%rbp)		/* a3 */\n\
  subq  $8, %rsp\n\
  pushq  32(%rbp)		/* a6 */\n\
  pushq  24(%rbp)		/* a5 */\n\
  pushq  16(%rbp)		/* a4 */\n\
  movq  -64(%rbp), %r8		/* a3 */\n\
  movq  -56(%rbp), %rdi		/* a2 */\n\
  movq  -48(%rbp), %rcx		/* a1 */\n\
  movl  -36(%rbp), %edx		/* nr */\n\
  movq  -32(%rbp), %rsi		/* new_th */\n\
  movq  -24(%rbp), %rdi		/* th */\n\
  call  ers_pre_syscall\n\
  addq  $32, %rsp\n\
  movq  32(%rbp), %r9		/* a6 */\n\
  movq  24(%rbp), %r8		/* a5 */\n\
  movq  16(%rbp), %r10		/* a4 */\n\
  movq  -64(%rbp), %rdx		/* a3 */\n\
  movq  -56(%rbp), %rsi		/* a2 */\n\
  movq  -48(%rbp), %rdi		/* a1 */\n\
  movl  -36(%rbp), %eax		/* nr */\n\
  cmpl  $"ERS_STRINGIFY (__NR_clone)", -36(%rbp);\n\
  je  .clone\n\
  syscall\n\
  movq  %rax, -8(%rbp)		/* res */\n\
  jmp  .post\n\
.clone:\n\
  subq  $8, %rsi\n\
  movq  8(%rbp), %r11\n\
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
  pushq  -8(%rbp)		/* res */\n\
  pushq  32(%rbp)		/* a6 */\n\
  pushq  24(%rbp)		/* a5 */\n\
  pushq  16(%rbp)		/* a4 */\n\
  movq  -64(%rbp), %r8		/* a3 */\n\
  movq  -56(%rbp), %rdi		/* a2 */\n\
  movq  -48(%rbp), %rcx		/* a1 */\n\
  movl  -36(%rbp), %edx		/* nr */\n\
  movq  -32(%rbp), %rsi		/* new_th */\n\
  movq  -24(%rbp), %rdi		/* th */\n\
  call  ers_post_syscall\n\
  addq  $32, %rsp\n\
  movq  -8(%rbp), %rax\n\
  leave\n\
  .cfi_def_cfa 7, 8\n\
  ret\n\
  .cfi_endproc\n\
  .size ers_syscall, .-ers_syscall\n"
);

#else

static long
ers_syscall (struct ers_thread *th, struct ers_thread *new_th, int nr,
	     long a1, long a2, long a3, long a4, long a5, long a6)
{
  long res = -1;
  ers_pre_syscall (th, new_th, nr, a1, a2, a3, a4, a5, a6);
  ers_post_syscall (th, new_th, nr, a1, a2, a3, a4, a5, a6, res);
  return res;
}

#endif

static void
ers_atomic_lock (struct ers_thread* th, void *mem, int size, int mo)
{
  struct atomic_locks *locks = &th->recorder->internal->atomic_locks;
  ers_lock (&locks->lock);

  ers_printf ("atomic lock %lx %lx %u %u\n", th, mem, size, mo);
  struct atomic_lock *lock = atomic_get (locks, mem, ERS_RBT_EQ | ERS_RBT_LT);
  if (! lock || (char *) lock->mem + lock->size <= (char *) mem)
    {
      ers_assert (ers_calloc (&th->recorder->internal->pool, sizeof *lock, (void **) &lock) == 0);
      lock->mem = mem;
      lock->size = size;
      atomic_insert (locks, lock);
    }
  else ers_assert (lock->mem == mem && lock->size == size);
}

static void
ers_atomic_unlock (struct ers_thread *th, void *mem)
{
  ers_printf ("atomic unlock %lx\n", mem);
  ers_unlock (&th->recorder->internal->atomic_locks.lock);
}

static void
ers_atomic_barrier (struct ers_thread *th, int mo)
{
  ers_printf ("atomic barrier %lx %u\n", th, mo);
}

static void
ers_debug (struct ers_thread* th, const char *text)
{
  ers_printf ("debug %lx %s\n", th, text);
}

static struct ers_internal internal;

static struct ers_recorder recorder = {

  0,
  ers_init_process,
  ers_init_thread,
  ers_fini_thread,
  ers_syscall,
  ers_atomic_lock,
  ers_atomic_unlock,
  ers_atomic_barrier,
  ers_debug,

  &internal
};

__attribute__ ((visibility ("default"))) struct ers_recorder *
ers_get_recorder (void)
{
  return &recorder;
}
