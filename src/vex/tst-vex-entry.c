#include <asm/unistd.h>

#include "vex-pub.h"
#include "vex-offsets.h"
#include "common.h"

#include "lib/syscall.h"
#include "lib/util.h"
#include "lib/util-common.h"
#include "lib/printf.h"

char __attribute__ ((aligned (16))) stack[8 * 1024 * 1024];

#define CHILD_STACK_SIZE (1024 * 1024)
char __attribute__ ((aligned (16))) child_stack[CHILD_STACK_SIZE];

/*
  movq	8(%rip), %rdi	\n\
  movq	%fs:0, %rax	\n\
  movq	%fs:0x100000000, %rax	\n\
  movq	%fs:(%rax), %rax	\n\

  call	1f		\n\
  ret	$16		\n\
  ret			\n\
  call	*8(%rax, %rbx, 4)		\n\
  jmp	*8(%rax, %rbx, 4)		\n\
  jmp	*%fs:8(%rax, %rbx, 4)		\n\
  jmp	*8(%rip)		\n\
  jmp	*%fs:8(%rip)		\n\
*/

#if 0

asm ("  .text		\n\
  .align 16		\n\
  .type tst, @function	\n\
tst:			\n\
  movq	%rdi, %rsi				\n\
  movq	$" _ERS_STR (ERI_ARCH_SET_FS) ", %rdi	\n\
  movl	$" _ERS_STR (__NR_arch_prctl) ", %eax	\n\
  syscall					\n\
  jmp	1f		\n\
  nop			\n\
1:			\n\
  movq	%fs:0, %rdi				\n\
  movl	$" _ERS_STR (__NR_exit) ", %eax		\n\
  syscall					\n\
  .size tst, .-tst	\n\
  .previous		\n"
);

#else

static long sys_child_tid __attribute__ ((used));

static void (*parent) (unsigned long arg) __attribute__ ((used));
static void (*child) (unsigned long arg) __attribute__ ((used));

#define CLONE_FLAGS \
  (ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SIGHAND	\
   | ERI_CLONE_THREAD | ERI_CLONE_SYSVSEM | ERI_CLONE_SETTLS)

asm ("  .text		\n\
  .align 16		\n\
  .type tst, @function	\n\
tst:			\n\
  movq	%rdi, %r8							\n\
  movq	$" _ERS_STR (CLONE_FLAGS) ", %rdi				\n\
  leaq	child_stack + " _ERS_STR (CHILD_STACK_SIZE) "(%rip), %rsi	\n\
  xorq	%rdx, %rdx							\n\
  xorq	%r10, %r10							\n\
  movl	$" _ERS_STR (__NR_clone) ", %eax				\n\
  syscall								\n\
  testq	%rax, %rax	\n\
  jl	1f		\n\
  jz	2f		\n\
3:			\n\
  movq	%rax, sys_child_tid(%rip)	\n\
  cmpq	$0, parent(%rip)		\n\
  je	5f		\n\
  mov	(%r8), %rdi	\n\
  call	*parent(%rip)	\n\
5:			\n\
  cmpq	$123, (%r8)	\n\
  jne	3b		\n\
  jmp	4f		\n\
1:			\n\
  movq	$0, %r15	\n\
  movq	$0, (%r15)	\n\
2:			\n\
  cmpq	$0, child(%rip)			\n\
  je	6f		\n\
  mov	%fs:0, %rdi	\n\
  call	*child(%rip)	\n\
6:			\n\
  movq	$123, %fs:0	\n\
4:			\n\
  movq	$0, %rdi				\n\
  movl	$" _ERS_STR (__NR_exit) ", %eax		\n\
  syscall					\n\
  .size tst, .-tst	\n\
  .previous		\n"
);

static void
tst_sigact_parent (unsigned long arg)
{
  int *p = (int *) arg;
  while (__atomic_load_n (p, __ATOMIC_ACQUIRE) != 1) continue;
  ERI_ASSERT_SYSCALL (exit_group, 0);
}

static int z;

asm ("  .text					\n\
  .align 16					\n\
  .type tst_sigact_child, @function		\n\
tst_sigact_child:				\n\
  jmp	tst_sigact_child_start			\n\
tst_sigact_child_start:				\n\
  movl	$" _ERS_STR (__NR_futex) ", %eax	\n\
  leaq	z(%rip), %rdi				\n\
  movq	$" _ERS_STR (ERI_FUTEX_WAIT) ", %rsi	\n\
  movq	$0, %rdx				\n\
  movq	$0, %r10				\n\
  syscall					\n\
tst_sigact_child_end:				\n\
  movq	$0, %r15				\n\
  movq	$0, (%r15)				\n\
  .size tst_sigact_child, .-tst_sigact_child	\n\
  .previous					\n"
);

/* static */ void tst_sigact_child (unsigned long arg);

#define SIGINTR ERI_SIGURG

static void
tst_sigact_brk (struct eri_vex_brk_desc *desc)
{
  int *i = *(int **) desc->data;

  extern char tst_sigact_child_start[];
  extern char tst_sigact_child_end[];

  if (desc->ctx->fsbase == (unsigned long) desc->data)
    {
      if (desc->type & ERI_VEX_BRK_PRE_EXEC
	  && desc->ctx->rip == (unsigned long) tst_sigact_child_start)
	{
	  __atomic_store_n (i, 1, __ATOMIC_RELEASE);

	  struct eri_sigset set;
	  eri_sigemptyset (&set);
	  while (! eri_sigset_p (&set, SIGINTR))
	    ERI_ASSERT_SYSCALL (rt_sigpending, &set, ERI_SIG_SETSIZE);
	}
      else if (desc->type & ERI_VEX_BRK_POST_EXEC
	       && desc->ctx->rip == (unsigned long) tst_sigact_child_end)
	{
	  eri_assert (desc->ctx->rsp == (unsigned long) (child_stack + CHILD_STACK_SIZE - sizeof (unsigned long)));
	  eri_assert (desc->ctx->rax == (unsigned long) -ERI_EINTR);
	  eri_assert (desc->ctx->rdi == (unsigned long) &z);
	  eri_assert (desc->ctx->rsi == ERI_FUTEX_WAIT);
	  eri_assert (desc->ctx->rdx == 0);
	  eri_assert (desc->ctx->r10 == 0);
	  *i = 2;
	}
    }
  else if (desc->type & ERI_VEX_BRK_EXIT_GROUP)
    {
      eri_assert (desc->ctx->rax == __NR_exit_group);
      eri_assert (desc->ctx->rdi == 0);
      eri_assert (*i == 2);
    }
}

asm ("  .text						\n\
  .align 16						\n\
  .type tst_sigact1_parent, @function			\n\
tst_sigact1_parent:					\n\
  jmp	tst_sigact1_parent_start			\n\
tst_sigact1_parent_start:				\n\
  movl	$" _ERS_STR (__NR_exit_group) ", %eax		\n\
  movq	$0, %rdi					\n\
  syscall						\n\
  .size tst_sigact1_parent, .-tst_sigact1_parent	\n\
  .previous						\n"
);

asm ("  .text					\n\
  .align 16					\n\
  .type tst_sigact1_child, @function		\n\
tst_sigact1_child:				\n\
  movl	$" _ERS_STR (__NR_futex) ", %eax	\n\
  leaq	z(%rip), %rdi				\n\
  movq	$" _ERS_STR (ERI_FUTEX_WAIT) ", %rsi	\n\
  movq	$0, %rdx				\n\
  movq	$0, %r10				\n\
  syscall					\n\
tst_sigact1_child_end:				\n\
  movq	$0, %r15				\n\
  movq	$0, (%r15)				\n\
  .size tst_sigact1_child, .-tst_sigact1_child	\n\
  .previous					\n"
);

/* static */ void tst_sigact1_parent (unsigned long arg);
/* static */ void tst_sigact1_child (unsigned long arg);

static void
tst_sigact1_proc_status_line (const void *ln, size_t sz, void *d)
{
  if (eri_strncmp (ln, "State:", eri_min (sz, eri_strlen ("State:"))) == 0
      && eri_strnstr (ln, "S (sleeping)", sz))
    *(char *) d = 1;
}

static void
tst_sigact1_brk (struct eri_vex_brk_desc *desc)
{
  int *i = *(int **) desc->data;

  extern char tst_sigact1_parent_start[];
  extern char tst_sigact1_child_end[];

  if (desc->ctx->fsbase == (unsigned long) desc->data)
    {
      if (desc->type & ERI_VEX_BRK_POST_EXEC
	  && desc->ctx->rip == (unsigned long) tst_sigact1_child_end)
	{
	  eri_assert (desc->ctx->rsp == (unsigned long) (child_stack + CHILD_STACK_SIZE - sizeof (unsigned long)));
	  eri_assert (desc->ctx->rax == (unsigned long) -ERI_EINTR);
	  eri_assert (desc->ctx->rdi == (unsigned long) &z);
	  eri_assert (desc->ctx->rsi == ERI_FUTEX_WAIT);
	  eri_assert (desc->ctx->rdx == 0);
	  eri_assert (desc->ctx->r10 == 0);
	  *i = 2;
	}
    }
  else if (desc->type & ERI_VEX_BRK_PRE_EXEC
	   && desc->ctx->rip == (unsigned long) tst_sigact1_parent_start)
    {
      size_t s = eri_strlen ("/proc/self/task/xxxxx/status") + 1;
      char path[s];
      eri_strcpy (path, "/proc/self/task/");
      s = eri_strlen ("/proc/self/task/");
      int j, k = 0;
      for (j = 10000; j > 0; j /= 10)
	if (sys_child_tid >= j || k != 0) path[s + k++] = '0' + (sys_child_tid / j) % 10;
      eri_assert (k <= 5);
      eri_strcpy (path + s + k, "/status");

      eri_assert_printf ("status: %s\n", path);

      char buf[1024];
      struct eri_buf b;
      eri_buf_static_init (&b, buf, sizeof buf);

      char sleep = 0;
      while (! sleep)
	eri_file_foreach_line (path, &b, tst_sigact1_proc_status_line, &sleep);

      eri_assert_printf ("sleep\n");
    }
  else if (desc->type & ERI_VEX_BRK_EXIT_GROUP)
    {
      eri_assert (desc->ctx->rax == __NR_exit_group);
      eri_assert (desc->ctx->rdi == 0);
      eri_assert (*i == 2);
    }
}

#endif

void *tst (void *);

void
brk (struct eri_vex_brk_desc *desc)
{
}

void __attribute__ ((visibility ("default")))
entry (void *rip, void *rsp, unsigned long fsbase)
{
  eri_dump_maps (ERI_STDOUT);

  unsigned long p = 0;

  size_t buf_size = 256 * 1024 * 1024;
  char *buf = (char *) ERI_ASSERT_SYSCALL_RES (
		mmap, 0, buf_size, ERI_PROT_READ | ERI_PROT_WRITE,
		ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);
  const char *path = "vex_data";

  int i = 0;
  struct eri_vex_desc desc = { buf, buf_size, 1, 4096, path, 0, 0, ~0 };
  if (rip == 0)
    {
      desc.comm.rip = (unsigned long) tst;
      desc.comm.rdi = (unsigned long) &p;
      if ((unsigned long) rsp == 0)
	desc.brk = brk;
      else if ((unsigned long) rsp == 1)
	{
	  parent = tst_sigact_parent;
	  child = tst_sigact_child;
	  p = (unsigned long) &i;
	  desc.brk = tst_sigact_brk;
	  desc.brk_data = &p;
	}
      else
	{
	  parent = tst_sigact1_parent;
	  child = tst_sigact1_child;
	  p = (unsigned long) &i;
	  desc.brk = tst_sigact1_brk;
	  desc.brk_data = &p;
	}
      desc.comm.rsp = (unsigned long) (stack + sizeof stack);
    }
  else
    {
      desc.comm.rip = (unsigned long) rip;
      desc.comm.rsp = (unsigned long) rsp;
      desc.comm.fsbase = fsbase;
    }

  /* eri_printf ("%lx %lx %lx\n", p, &p, tst (&p)); */

  if (ERI_SYSCALL_ERROR_P (ERI_SYSCALL (mkdir, path, ERI_S_IRWXU)))
    eri_assert (eri_fprintf (ERI_STDERR, "failed to create %s\n", path) == 0);
  eri_vex_enter (&desc);
  eri_assert (0);
}
