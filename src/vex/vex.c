#include <stdarg.h>
#include <asm/unistd.h>

#include "vex-pub.h"

#include "vex.h"
#include "vex-offsets.h"

#include "recorder.h"
#include "common.h"

#include "lib/util.h"
#include "lib/printf.h"
#include "lib/malloc.h"
#include "lib/rbtree.h"
#include "lib/list.h"
#include "lib/syscall.h"

#include "xed/xed-util.h"
#include "xed/xed-interface.h"

struct vex;

struct context
{
  struct vex_context ctx;

  void *mp;
  unsigned long id;

  struct vex *vex;

  void *stack;

  struct context *child;

  int log;
};

#define CTX	_ERS_STR (VEX_CTX_CTX)

static void cprintf (int log, const char *fmt, ...);

static void
vex_xed_abort (const char *msg, const char *file, int line, void *other)
{
  struct context *c;
  asm ("movq	%%fs:" CTX ", %0" : "=r" (c));
  cprintf (c->log, "xed_abort[%s:%u]: %s\n", file, line, msg);
  eri_assert (0);
}

static void
vex_decode (unsigned long rip, size_t pagesize,
	    xed_decoded_inst_t *xd)
{
  xed_decoded_inst_zero (xd);
  xed_decoded_inst_set_mode (xd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  unsigned int bytes = eri_max (eri_round_up (rip + 1, pagesize) - rip,
				XED_MAX_INSTRUCTION_BYTES);
  xed_error_enum_t error = xed_decode (xd, (void *) rip, bytes);
  if (error == XED_ERROR_BUFFER_TOO_SHORT)
    error = xed_decode (xd, (void *) rip, XED_MAX_INSTRUCTION_BYTES);
  eri_assert (error == XED_ERROR_NONE);
}

static void
vex_dump_inst (int log, unsigned long rip, const xed_decoded_inst_t *xd)
{
  xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum (xd);
  cprintf (log, "iclass: %u %s,",
	   xed_iform_to_iclass (iform),
	   xed_iform_to_iclass_string_att (iform));

  xed_uint_t length = xed_decoded_inst_get_length (xd);
  xed_uint32_t eow = xed_operand_values_get_effective_operand_width (xd);

  const xed_inst_t *xi = xed_decoded_inst_inst (xd);
  int noperands = xed_inst_noperands (xi);
  cprintf (log, "length: %u, eow: %u, noperands: %u\n",
	   length, eow, noperands);

  int i;
  for (i = 0; i < noperands; ++i)
    {
      int idx = noperands - i - 1;
      const xed_operand_t *op = xed_inst_operand (xi, idx);
      xed_operand_enum_t op_name = xed_operand_name (op);
      cprintf (log, "  opname: %s, ", xed_operand_enum_t2str (op_name));

      if (op_name == XED_OPERAND_SEG0
	  || op_name == XED_OPERAND_SEG1
	  || op_name == XED_OPERAND_INDEX
	  || op_name == XED_OPERAND_BASE0
	  || op_name == XED_OPERAND_BASE1
	  || (op_name >= XED_OPERAND_REG0 && op_name <= XED_OPERAND_REG8))
	{
	  xed_reg_enum_t reg = xed_decoded_inst_get_reg (xd, op_name);
	  cprintf (log, "operand: %s, ", xed_reg_enum_t2str (reg));
	}
      else if (op_name == XED_OPERAND_MEM0 || op_name == XED_OPERAND_AGEN)
	{
	  xed_reg_enum_t base = xed_decoded_inst_get_base_reg (xd, 0);
	  xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg (xd, 0);
	  xed_reg_enum_t index = xed_decoded_inst_get_index_reg (xd, 0);
	  xed_int64_t disp = xed_operand_values_get_memory_displacement_int64 (xd);
	  unsigned int disp_bits = xed_operand_values_get_memory_displacement_length_bits (xd);
	  xed_uint_t bytes = xed_decoded_inst_operand_length_bits (xd, idx) >> 3;

	  eri_assert (base != XED_REG_FSBASE && base != XED_REG_GSBASE);
	  eri_assert (seg != XED_REG_FSBASE && seg != XED_REG_GSBASE);
	  eri_assert (index != XED_REG_FSBASE && index != XED_REG_GSBASE);

	  cprintf (log, "base: %s, ", xed_reg_enum_t2str (base));
	  cprintf (log, "seg: %s, ", xed_reg_enum_t2str (seg));
	  cprintf (log, "index: %s, ", xed_reg_enum_t2str (index));
	  cprintf (log, "disp: %lx, %lx, ", disp, ~disp + 1);
	  cprintf (log, "disp_bits: %u, ", disp_bits);
	  cprintf (log, "bytes: %u, ", bytes);
	}
      else if (op_name == XED_OPERAND_MEM1)
	{
	  xed_reg_enum_t base = xed_decoded_inst_get_base_reg (xd, 1);
	  xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg (xd, 1);
	  xed_uint_t bytes = xed_decoded_inst_operand_length_bits (xd, idx) >> 3;

	  eri_assert (base != XED_REG_FSBASE && base != XED_REG_GSBASE);
	  eri_assert (seg != XED_REG_FSBASE && seg != XED_REG_GSBASE);

	  cprintf (log, "base: %s, ", xed_reg_enum_t2str (base));
	  cprintf (log, "seg: %s, ", xed_reg_enum_t2str (seg));
	  cprintf (log, "bytes: %u, ", bytes);
	}
      else if (op_name == XED_OPERAND_RELBR)
	{
	  xed_int32_t disp = xed_decoded_inst_get_branch_displacement (xd);

	  cprintf (log, "disp: %x, %x, ", disp, ~disp + 1);
	  cprintf (log, "addr: %lx, ", rip + length + disp);
	}
      else if (op_name == XED_OPERAND_IMM0)
	{
	  xed_uint64_t imm = xed_decoded_inst_get_unsigned_immediate (xd);
	  xed_uint_t is_signed = xed_decoded_inst_get_immediate_is_signed (xd);
	  xed_uint_t bytes = xed_decoded_inst_get_immediate_width (xd);

	  cprintf (log, "imm: %lx, %lu, %lx, %lu, ", imm, imm, ~imm + 1, ~imm + 1);
	  cprintf (log, "is_signed: %u, ", is_signed);
	  cprintf (log, "bytes: %u, ", bytes);
	}

      xed_operand_action_enum_t action = xed_decoded_inst_operand_action (xd, idx);
      cprintf (log, "action: %s\n", xed_operand_action_enum_t2str (action));
    }
}

struct entry
{
  unsigned long rip;
  ERI_RBT_NODE_FIELDS (entry, struct entry)

  int trans_lock;
  unsigned long *inst_rips;
  void *insts;

  unsigned refs;
};

struct vex
{
  size_t pagesize;
  const char *path;

  void *mmap;
  size_t mmap_size;
  char group_exiting;

  int exit_stack_lock;
  void *exit_stack_top;

  int entrys_lock;
  ERI_RBT_TREE_FIELDS (entry, struct entry)

  unsigned long context_id;
  unsigned ncontexts;

  struct eri_mtpool pool;
  struct eri_mtpool epool;

  int max_inst_count;
};

ERI_DEFINE_RBTREE (static, entry, struct vex, struct entry, unsigned long, eri_less_than)

/* static */ void vex_syscall (void);
/* static */ void vex_back (void);

static void
cprintf (int log, const char *fmt, ...)
{
  return;
  va_list arg;
  va_start (arg, fmt);
  eri_assert (eri_vfprintf (log, fmt, arg) == 0);
  va_end (arg);
};

static struct context *
alloc_context (struct vex *v)
{
  void *p;
  struct context *c = (struct context *) eri_round_up (
      (unsigned long) (p = eri_assert_mtcalloc (&v->pool, sizeof *c + 48)),
      64);
  c->mp = p;
  c->ctx.ctx = c;

  c->ctx.syscall = (unsigned long) vex_syscall;
  c->ctx.back = (unsigned long) vex_back;
  c->stack = eri_assert_mtcalloc (&v->pool, 2 * 1024 * 1024);
  c->ctx.top = (unsigned long) c->stack + 2 * 1024 * 1024;

  c->vex = v;
  return c;
}

static struct context * __attribute__ ((used))
alloc_child_context (struct context *c)
{
  struct context *cc = alloc_context (c->vex);
  cc->ctx.comm.rip = c->ctx.comm.rip;
  cc->ctx.comm.r8 = c->ctx.comm.r8;
  cc->ctx.comm.fsbase = c->ctx.comm.r8;
  cc->ctx.ret = c->ctx.ret;
  c->child = cc;
  return cc;
}

static void
start_context (struct context *c)
{
  struct vex *v = c->vex;
  c->id = __atomic_fetch_add (&v->context_id, 1, __ATOMIC_RELAXED);
  c->log = eri_open_path (v->path, "vex-log-", ERI_OPEN_WITHID, c->id);
}

static void
free_context (struct context *c)
{
  eri_assert_mtfree (&c->vex->pool, c->stack);
  eri_assert_mtfree (&c->vex->pool, c->mp);
}

static void __attribute__ ((used))
free_child_context (struct context *c)
{
  free_context (c->child);
}

static void vex_loop (struct context *c);

static void __attribute__ ((used))
vex_start_child (struct context *c)
{
  __atomic_add_fetch (&c->vex->ncontexts, 1, __ATOMIC_ACQUIRE);
  start_context (c);
  vex_loop (c);
}

#define VEX_EXIT_GROUP	0
#define VEX_EXIT_WAIT	1
#define VEX_EXIT_SELF	2

static void __attribute__ ((used))
vex_exit_alt_stack (int type, unsigned long status, int nr, struct context *c)
{
  cprintf (c->log, "exit %u\n", type);

  struct vex *v = c->vex;
  eri_assert (eri_fclose (c->log) == 0);
  eri_assert_mtfree (&v->pool, c->stack);
  eri_assert_mtfree (&v->pool, c->mp);

  __atomic_add_fetch (&v->ncontexts, -1, __ATOMIC_RELEASE);
  if (type == VEX_EXIT_GROUP)
    {
      eri_assert (eri_printf ("vex pool used: %lu\n", v->pool.pool.used) == 0);
      eri_assert (eri_fini_pool (&v->pool.pool) == 0);
      if (v->mmap)
	asm ("  movq	%q0, %%rdi\n\t"
	     "  movq	%q1, %%rsi\n\t"
	     "  movl	$" _ERS_STR (__NR_munmap) ", %%eax\n\t"
	     "  syscall\n\t"
	     "  cmpq	$-4095, %%rax\n\t"
	     "  jb	1f\n\t"
	     "  movq	$0, %%r11\n\t"
	     "  movq	$0, (%%r11)\n\t"
	     "1:\n\t"
	     "  movq	%q2, %%rdi\n\t"
	     "  movl	%3, %%eax\n\t"
	     "  syscall\n\t"
	     : : "r" (v->mmap), "r" (v->mmap_size), "r" (status), "r" (nr)
	     : "rdi", "rsi", "rax");
      else
	ERI_SYSCALL_NCS (nr, status);
    }
  else if (type == VEX_EXIT_WAIT)
      asm ("  movl	$0, (%q0)\n\t"
	   "  movq	%q0, %%rdi\n\t"
	   "  movq	$" _ERS_STR (ERI_FUTEX_WAKE) ", %%rsi\n\t"
	   "  movq	$1, %%rdx\n\t"
	   "  movl	$" _ERS_STR (__NR_futex)", %%eax\n\t"
	   "  syscall\n\t"
	   "  cmpq	$-4095, %%rax\n\t"
	   "  jb	1f\n\t"
	   "  movq	$0, %%r11\n\t"
	   "  movq	$0, (%%r11)\n\t"
	   "1:\n\t"
	   "  jmp	1b\n\t"
	   : : "r" (&v->exit_stack_lock)
	   : "rdi", "rsi", "rdx", "rax");
  else
      asm ("  movl	$0, (%q0)\n\t"
	   "  movq	%q0, %%rdi\n\t"
	   "  movq	$" _ERS_STR (ERI_FUTEX_WAKE) ", %%rsi\n\t"
	   "  movq	$1, %%rdx\n\t"
	   "  movl	$" _ERS_STR (__NR_futex)", %%eax\n\t"
	   "  syscall\n\t"
	   "  cmpq	$-4095, %%rax\n\t"
	   "  jb	1f\n\t"
	   "  movq	$0, %%r11\n\t"
	   "  movq	$0, (%%r11)\n\t"
	   "1:\n\t"
	   "  movq	%q1, %%rdi\n\t"
	   "  movl	$" _ERS_STR (__NR_exit) ", %%eax\n\t"
	   "  syscall\n\t"
	   : : "r" (&v->exit_stack_lock), "r" (status)
	   : "rdi", "rsi", "rdx", "rax");
  eri_assert (0);
}

#define VEX_EXIT_ALT_STACK(c, type, status, nr) \
  do {											\
    struct context *__c = c;								\
    struct vex *__v = c->vex;								\
    eri_lock (&__v->exit_stack_lock, 1);						\
    asm ("movq	%q0, %%rsp\n\t"								\
	 "movl	%1, %%edi\n\t"								\
	 "movq	%q2, %%rsi\n\t"								\
	 "movl	%3, %%edx\n\t"								\
	 "movq	%q4, %%rcx\n\t"								\
	 "call	vex_exit_alt_stack"							\
	 : : "r" (__v->exit_stack_top), "r" (type), "r" (status), "r" (nr), "r" (__c)	\
	 : "rsp", "rdi", "rsi", "rdx", "rcx");						\
  } while (0)

static void __attribute__ ((used))
vex_exit (unsigned long status, int nr, struct context *c)
{
  struct vex *v = c->vex;

  int type = VEX_EXIT_SELF;
  char grp = nr == __NR_exit_group || c->id == 0;
  if (grp)
    {
      if (__atomic_exchange_n (&v->group_exiting, 1, __ATOMIC_ACQ_REL) == 0)
	{
	  while (__atomic_load_n (&v->ncontexts, __ATOMIC_ACQUIRE) != 1)
	    continue;

	  struct entry *e, *ne;
	  ERI_RBT_FOREACH_SAFE (entry, v, e, ne)
	    {
	      entry_rbt_remove (v, e);
	      eri_assert (eri_free (&v->pool.pool, e->inst_rips) == 0);
	      eri_assert (eri_free (&v->epool.pool, e->insts) == 0);
	      eri_assert (eri_free (&v->pool.pool, e) == 0);
	    }

	  eri_assert (eri_printf ("vex epool used: %lu\n", v->epool.pool.used) == 0);
	  eri_assert (eri_fini_pool (&v->epool.pool) == 0);

	  type = VEX_EXIT_GROUP;
	}
      else
	/* Exiting is already started by another context.  */
	type = VEX_EXIT_WAIT;
    }

  VEX_EXIT_ALT_STACK (c, type, status, nr);
}

#define RAX	_ERS_STR (VEX_CTX_RAX)
#define RCX	_ERS_STR (VEX_CTX_RCX)
#define RDX	_ERS_STR (VEX_CTX_RDX)
#define RBX	_ERS_STR (VEX_CTX_RBX)
#define RSP	_ERS_STR (VEX_CTX_RSP)
#define RBP	_ERS_STR (VEX_CTX_RBP)
#define RSI	_ERS_STR (VEX_CTX_RSI)
#define RDI	_ERS_STR (VEX_CTX_RDI)
#define R8	_ERS_STR (VEX_CTX_R8)
#define R9	_ERS_STR (VEX_CTX_R9)
#define R10	_ERS_STR (VEX_CTX_R10)
#define R11	_ERS_STR (VEX_CTX_R11)
#define R12	_ERS_STR (VEX_CTX_R12)
#define R13	_ERS_STR (VEX_CTX_R13)
#define R14	_ERS_STR (VEX_CTX_R14)
#define R15	_ERS_STR (VEX_CTX_R15)

#define RFLAGS	_ERS_STR (VEX_CTX_RFLAGS)
#define FSBASE	_ERS_STR (VEX_CTX_FSBASE)

#define XSAVE	_ERS_STR (VEX_CTX_XSAVE)

#define INSTS	_ERS_STR (VEX_CTX_INSTS)
#define RET	_ERS_STR (VEX_CTX_RET)
#define TOP	_ERS_STR (VEX_CTX_TOP)

asm ("  .text						\n\
  .align 16						\n\
  .type vex_execute, @function				\n\
vex_execute:						\n\
  .cfi_startproc					\n\
  .cfi_undefined %rip					\n\
  pushq	%rbx						\n\
  pushq	%rbp						\n\
  pushq	%r12						\n\
  pushq	%r13						\n\
  pushq	%r14						\n\
  pushq	%r15						\n\
							\n\
  leaq	1f(%rip), %rax					\n\
  movq	%rax, %fs:" RET "				\n\
  movq	%rsp, %fs:" TOP "				\n\
  movq	$-1, %rdx					\n\
  movq	$-1, %rax					\n\
  xrstor	%fs:" XSAVE "				\n\
  pushq	%fs:" RFLAGS "					\n\
  popfq							\n\
  movq	%fs:" RAX ", %rax				\n\
  movq	%fs:" RCX ", %rcx				\n\
  movq	%fs:" RDX ", %rdx				\n\
  movq	%fs:" RBX ", %rbx				\n\
  movq	%fs:" RSP ", %rsp				\n\
  movq	%fs:" RBP ", %rbp				\n\
  movq	%fs:" RSI ", %rsi				\n\
  movq	%fs:" RDI ", %rdi				\n\
  movq	%fs:" R8 ", %r8					\n\
  movq	%fs:" R9 ", %r9					\n\
  movq	%fs:" R10 ", %r10				\n\
  movq	%fs:" R11 ", %r11				\n\
  movq	%fs:" R12 ", %r12				\n\
  movq	%fs:" R13 ", %r13				\n\
  movq	%fs:" R14 ", %r14				\n\
  movq	%fs:" R15 ", %r15				\n\
  jmp	*%fs:" INSTS "					\n\
1:							\n\
  popq	%r15						\n\
  popq	%r14						\n\
  popq	%r13						\n\
  popq	%r12						\n\
  popq	%rbp						\n\
  popq	%rbx						\n\
  ret							\n\
  .cfi_endproc						\n\
  .size vex_execute, .-vex_execute			\n\
  .previous						\n"
);

/* static */ void vex_execute (void);

#define MIN_CLONE_FLAGS \
  (ERI_CLONE_VM | ERI_CLONE_FS | ERI_CLONE_FILES | ERI_CLONE_SIGHAND	\
   | ERI_CLONE_THREAD | ERI_CLONE_SYSVSEM)
#define MAX_CLONE_FLAGS \
  (MIN_CLONE_FLAGS | ERI_CLONE_SETTLS					\
   | ERI_CLONE_PARENT_SETTID | ERI_CLONE_CHILD_CLEARTID)

asm ("  .text						\n\
  .align 16						\n\
  .type vex_syscall, @function				\n\
vex_syscall:						\n\
  cmpl	$" _ERS_STR (__NR_clone) ", %eax		\n\
  je	.clone						\n\
  cmpl	$" _ERS_STR (__NR_exit) ", %eax			\n\
  je	.exit						\n\
  cmpl	$" _ERS_STR (__NR_exit_group) ", %eax		\n\
  je	.exit						\n\
  cmpl	$" _ERS_STR (__NR_arch_prctl) ", %eax		\n\
  je	.arch_prctl					\n\
  jmp	.syscall					\n\
							\n\
.clone:							\n\
  movq	%rdi, %r11					\n\
  andq	$" _ERS_STR (MIN_CLONE_FLAGS) ", %r11		\n\
  cmpq	$" _ERS_STR (MIN_CLONE_FLAGS) ", %r11		\n\
  jne	.assert_failed					\n\
  movq	%rdi, %r11					\n\
  andq	$~" _ERS_STR (MAX_CLONE_FLAGS) ", %r11		\n\
  cmpq	$0, %r11					\n\
  jne	.assert_failed					\n\
							\n\
  movq	%rax, %fs:" RAX "				\n\
  movq	%rdi, %fs:" RDI "				\n\
  movq	%rsi, %fs:" RSI "				\n\
  movq	%rdx, %fs:" RDX "				\n\
  movq	%rcx, %fs:" RCX "				\n\
  movq	%r8, %fs:" R8 "					\n\
  movq	%r9, %fs:" R9 "					\n\
  movq	%r10, %fs:" R10 "				\n\
							\n\
  movq	%rsp, %fs:" RSP "				\n\
  movq	%fs:" TOP ", %rsp				\n\
  movq	%fs:" CTX ", %rdi				\n\
  call	alloc_child_context				\n\
  movq	%fs:" RSP ", %rsp				\n\
							\n\
  movq	%rax, %r8					\n\
  movq	%fs:" RAX ", %rax				\n\
  movq	%fs:" RDI ", %rdi				\n\
  movq	%fs:" RSI ", %rsi				\n\
  movq	%fs:" RDX ", %rdx				\n\
  movq	%fs:" R10 ", %r10				\n\
							\n\
  syscall						\n\
  movq	%fs:" R8 ", %r8					\n\
  cmpq	$-4095, %rax					\n\
  jae	.clone_failed					\n\
  testq	%rax, %rax					\n\
  jz	.clone_child					\n\
  jmp	vex_back					\n\
							\n\
.clone_failed:						\n\
  leaq	1f(%rip), %r11					\n\
  xchg	%fs:" RET ", %r11				\n\
  jmp	vex_back					\n\
1:							\n\
  movq	%fs:" CTX ", %rdi				\n\
  call	free_child_context				\n\
  jmp	*%fs:" R11 "					\n\
							\n\
.clone_child:						\n\
  leaq	1f(%rip), %r11					\n\
  movq	%r11, %fs:" RET "				\n\
  jmp	vex_back					\n\
1:							\n\
  movq	%fs:" CTX ", %rdi				\n\
  call	vex_start_child					\n\
  jmp	.assert_failed					\n\
							\n\
.exit:							\n\
  movq	%fs:" TOP ", %rsp				\n\
  movl	%eax, %esi					\n\
  movq	%fs:" CTX ", %rdx				\n\
  call	vex_exit					\n\
  jmp	.assert_failed					\n\
							\n\
.arch_prctl:						\n\
  cmpq	$" _ERS_STR (ERI_ARCH_SET_FS) ", %rdi		\n\
  je	.arch_prctl_set_fs				\n\
  cmpq	$" _ERS_STR (ERI_ARCH_GET_FS) ", %rdi		\n\
  je	.arch_prctl_get_fs				\n\
  jmp	.syscall					\n\
.arch_prctl_set_fs:					\n\
  movq	%rsi, %fs:" FSBASE "				\n\
  xorq	%rax, %rax					\n\
  jmp	vex_back					\n\
.arch_prctl_get_fs:					\n\
  movq	%fs:" FSBASE ", %rax				\n\
  movq	%rax, (%rsi)					\n\
  xorq	%rax, %rax					\n\
  jmp	vex_back					\n\
							\n\
.syscall:						\n\
  syscall						\n\
  jmp	vex_back					\n\
							\n\
.assert_failed:						\n\
  movq	$0, %r15					\n\
  movq	$0, (%r15)					\n\
  .size vex_syscall, .-vex_syscall			\n\
  .previous						\n"
);

asm ("  .text						\n\
  .align 16						\n\
vex_back:						\n\
  movq	%rax, %fs:" RAX "				\n\
  movq	%rcx, %fs:" RCX "				\n\
  movq	%rdx, %fs:" RDX "				\n\
  movq	%rbx, %fs:" RBX "				\n\
  movq	%rsp, %fs:" RSP "				\n\
  movq	%rbp, %fs:" RBP "				\n\
  movq	%rsi, %fs:" RSI "				\n\
  movq	%rdi, %fs:" RDI "				\n\
  movq	%r8, %fs:" R8 "					\n\
  movq	%r9, %fs:" R9 "					\n\
  movq	%r10, %fs:" R10 "				\n\
  movq	%r11, %fs:" R11 "				\n\
  movq	%r12, %fs:" R12 "				\n\
  movq	%r13, %fs:" R13 "				\n\
  movq	%r14, %fs:" R14 "				\n\
  movq	%r15, %fs:" R15 "				\n\
  movq	%fs:" TOP ", %rsp				\n\
  pushfq						\n\
  popq	%fs:" RFLAGS "					\n\
  movq	$-1, %rdx					\n\
  movq	$-1, %rax					\n\
  xsave	%fs:" XSAVE "					\n\
  jmp	*%fs:" RET "					\n\
  .previous						\n"
);

#if 0
  /* cmp	%rax, $158 */
  xed_encoder_request_set_iclass (&xe, XED_ICLASS_CMP);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, XED_REG_RAX);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

  xed_encoder_request_set_uimm0 (&xe, 158, 4);
  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_IMM0);
#endif
#if 0
  /* movq	%rax, %fs:RAX */
  xed_encoder_request_set_iclass (&xe, XED_ICLASS_MOV);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_memory_operand_length (&xe, 8);
  xed_encoder_request_set_mem0 (&xe);
  xed_encoder_request_set_seg0 (&xe, XED_REG_FS);
  xed_encoder_request_set_memory_displacement (&xe, VEX_CTX_RAX, 4);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_MEM0);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, XED_REG_RAX);
  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_REG0);
#endif

static char
vex_is_transfer (xed_iclass_enum_t iclass)
{
  return iclass == XED_ICLASS_JB
	 || iclass == XED_ICLASS_JBE
	 || iclass == XED_ICLASS_JCXZ
	 || iclass == XED_ICLASS_JECXZ
	 || iclass == XED_ICLASS_JL
	 || iclass == XED_ICLASS_JLE
	 || iclass == XED_ICLASS_JMP
	 || iclass == XED_ICLASS_JNB
	 || iclass == XED_ICLASS_JNBE
	 || iclass == XED_ICLASS_JNL
	 || iclass == XED_ICLASS_JNLE
	 || iclass == XED_ICLASS_JNO
	 || iclass == XED_ICLASS_JNP
	 || iclass == XED_ICLASS_JNS
	 || iclass == XED_ICLASS_JNZ
	 || iclass == XED_ICLASS_JO
	 || iclass == XED_ICLASS_JP
	 || iclass == XED_ICLASS_JRCXZ
	 || iclass == XED_ICLASS_JS
	 || iclass == XED_ICLASS_JZ
	 || iclass == XED_ICLASS_LOOP
	 || iclass == XED_ICLASS_LOOPE
	 || iclass == XED_ICLASS_LOOPNE
	 || iclass == XED_ICLASS_CALL_NEAR
	 || iclass == XED_ICLASS_RET_NEAR;
}

struct encode_buf
{
  int log;
  struct eri_mtpool *pool;

  size_t size;
  xed_uint8_t *p;
  size_t off;
};

static void
inc_encode_buf (struct encode_buf *b)
{
  eri_assert (b->pool);

  b->size *= 2;

  xed_uint8_t *t = b->p;
  b->p = eri_assert_mtmalloc (b->pool, b->size);
  eri_memcpy (b->p, t, b->off);

  eri_assert_mtfree (b->pool, t);
}

static void
vex_encode (struct encode_buf *b, xed_encoder_request_t *xe)
{
  while (b->size - b->off < XED_MAX_INSTRUCTION_BYTES)
    inc_encode_buf (b);

  unsigned int l;
  xed_error_enum_t error = xed_encode (xe, b->p + b->off,
				       XED_MAX_INSTRUCTION_BYTES, &l);
  if (error != XED_ERROR_NONE)
    {
      cprintf (b->log, "encode error: %s\n", xed_error_enum_t2str (error));
      eri_assert (0);
    }

  b->off += l;
}

static void
vex_concat (struct encode_buf *b1, const struct encode_buf *b2)
{
  while (b1->size - b1->off < b2->off)
    inc_encode_buf (b1);

  eri_memcpy (b1->p + b1->off, b2->p, b2->off);
  b1->off += b2->off;
}

#define REG_DISP(r) (VEX_CTX_RAX + (r) * 8)

static void
vex_encode_mov_reg (struct encode_buf *b,
		    xed_reg_enum_t reg, char save, long offset)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_MOV);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, reg);
  xed_encoder_request_set_operand_order (&xe, save, XED_OPERAND_REG0);

  xed_encoder_request_set_memory_operand_length (&xe, 8);
  xed_encoder_request_set_mem0 (&xe);
  xed_encoder_request_set_seg0 (&xe, XED_REG_FS);
  xed_encoder_request_set_memory_displacement (&xe, offset, 4);
  xed_encoder_request_set_operand_order (&xe, ! save, XED_OPERAND_MEM0);

  vex_encode (b, &xe);
}

static void
vex_encode_save_gpr (struct encode_buf *b, xed_reg_enum_t reg)
{
  /* movq	%reg, %fs:REG */
  vex_encode_mov_reg (b, reg, 1, REG_DISP (reg - XED_REG_RAX));
}

static void
vex_encode_restore_gpr (struct encode_buf *b, xed_reg_enum_t reg)
{
  /* movq	%fs:REG, %reg */
  vex_encode_mov_reg (b, reg, 0, REG_DISP (reg - XED_REG_RAX));
}

static void
vex_encode_save_rip (struct encode_buf *b, xed_reg_enum_t reg)
{
  /* movq	%reg, %fs:RIP */
  vex_encode_mov_reg (b, reg, 1, VEX_CTX_RIP);
}

static void
vex_encode_switch_to_internal_stack (struct encode_buf *b)
{
  /*
     movq	%rsp, %fs:RSP
     movq	%fs:TOP, %rsp
  */
  vex_encode_save_gpr (b, XED_REG_RSP);
  vex_encode_mov_reg (b, XED_REG_RSP, 0, VEX_CTX_TOP);
}

static void
vex_encode_save_rflags (struct encode_buf *b)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  /*
     pushfq
     popq	%fs:RFLAGS
  */

  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_PUSHFQ);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  vex_encode (b, &xe);

  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_POP);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_memory_operand_length (&xe, 8);
  xed_encoder_request_set_mem0 (&xe);
  xed_encoder_request_set_seg0 (&xe, XED_REG_FS);
  xed_encoder_request_set_memory_displacement (&xe, VEX_CTX_RFLAGS, 4);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_MEM0);

  vex_encode (b, &xe);
}

static void
vex_encode_push (struct encode_buf *b, long offset)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  /* pushq	%fs:offset */
  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_PUSH);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_memory_operand_length (&xe, 8);
  xed_encoder_request_set_mem0 (&xe);
  xed_encoder_request_set_seg0 (&xe, XED_REG_FS);
  xed_encoder_request_set_memory_displacement (&xe, offset, 4);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_MEM0);

  vex_encode (b, &xe);
}

static void
vex_encode_restore_rflags (struct encode_buf *b)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  /*
     pushq	%fs:RFLAGS
     popfq
  */

  vex_encode_push (b, VEX_CTX_RFLAGS);

  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_POPFQ);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  vex_encode (b, &xe);
}

#define A_B	0x1
#define A_W	0x2
#define A_D	0x4
#define A_Q	0x8

static xed_uint_t
get_disp_nbytes (long disp, int acc)
{
  if (acc & A_B && disp <= 0x7f && disp >= -0x80) return 1;
  else if (acc & A_W && disp <= 0x7fff && disp >= -0x8000) return 2;
  else if (acc & A_D && disp <= 0x7fffffff && disp >= -0x7fffffff - 1) return 4;
  else if (acc & A_Q) return 8;
  else eri_assert (0);
  return 0;
}

static xed_uint_t
get_uimm_nbytes (unsigned long uimm, int acc)
{
  if (acc & A_B && uimm <= 0xff) return 1;
  else if (acc & A_W && uimm <= 0xffff) return 2;
  else if (acc & A_D && uimm <= 0xffffffff) return 4;
  else if (acc & A_Q) return 8;
  else eri_assert (0);
  return 0;
}

static void
vex_encode_set_rip_tmp (struct encode_buf *b, xed_reg_enum_t tmp,
			unsigned long rip)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  /* movq	$rip, %tmp */
  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_MOV);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, tmp);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

  xed_encoder_request_set_uimm0 (&xe, rip,
				 get_uimm_nbytes (rip, A_D | A_Q));
  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_IMM0);

  vex_encode (b, &xe);
}

static void
vex_encode_push_reg (struct encode_buf *b, xed_reg_enum_t reg)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  /* pushq	%reg */
  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_PUSH);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, reg);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

  vex_encode (b, &xe);
}

static void
vex_encode_lea_disp (struct encode_buf *b, xed_reg_enum_t reg,
		     xed_int32_t disp)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  /* leaq	disp(%reg), %reg */
  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_LEA);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, reg);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

  xed_encoder_request_set_agen (&xe);
  xed_encoder_request_set_base0 (&xe, reg);
  xed_encoder_request_set_memory_displacement (&xe, disp, 4);
  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_AGEN);

  vex_encode (b, &xe);
}

static void
vex_encode_jmp (struct encode_buf *b, long offset)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  /* jmp	*%fs:offset */
  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_JMP);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_memory_operand_length (&xe, 8);
  xed_encoder_request_set_mem0 (&xe);
  xed_encoder_request_set_seg0 (&xe, XED_REG_FS);
  xed_encoder_request_set_memory_displacement (&xe, offset, 4);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_MEM0);

  vex_encode (b, &xe);
}

#define COPY_SEG	0x1
#define COPY_BASE	0x2
#define COPY_INDEX	0x4
#define COPY_SCALE	0x8
#define COPY_DISP	0x10

static void
vex_copy_mem0 (xed_encoder_request_t *xe, const xed_decoded_inst_t *xd,
	       int flags, xed_reg_enum_t rip_tmp)
{
  if (flags & COPY_SEG)
    xed_encoder_request_set_seg0 (xe, xed_decoded_inst_get_seg_reg (xd, 0));
  if (flags & COPY_BASE)
    {
      xed_reg_enum_t base = xed_decoded_inst_get_base_reg (xd, 0);
      eri_assert ((base == XED_REG_RIP) ^ (rip_tmp == XED_REG_INVALID));
      xed_encoder_request_set_base0 (xe, base == XED_REG_RIP ? rip_tmp : base);
    }
  if (flags & COPY_INDEX)
    xed_encoder_request_set_index (xe, xed_decoded_inst_get_index_reg (xd, 0));
  if (flags & COPY_SCALE)
    xed_encoder_request_set_scale (xe, xed_decoded_inst_get_scale (xd, 0));
  if (flags & COPY_DISP)
    xed_encoder_request_set_memory_displacement (
      xe,
      xed_decoded_inst_get_memory_displacement (xd, 0),
      xed_decoded_inst_get_memory_displacement_width (xd, 0));
}

static void
vex_encode_calc_fsbased_mem (struct encode_buf *b, const xed_decoded_inst_t *xd,
			     xed_reg_enum_t tmp, xed_reg_enum_t rip_tmp)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  /*
     movq	%tmp, %fs:TMP
     movq	%rsp, %fs:RSP
     movq	%fs:TOP, %rsp
     pushfq
     popq	%fs:RFLAGS
     leaq	mem, %tmp
     addq	%fs:FSBASE, %tmp
     pushq	%fs:RFLAGS
     popfq
     movq	%fs:RSP, %rsp
  */

  vex_encode_switch_to_internal_stack (b);
  vex_encode_save_rflags (b);

  xed_decoded_inst_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_LEA);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, tmp);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

  xed_encoder_request_set_agen (&xe);
  vex_copy_mem0 (&xe, xd, ~COPY_SEG, rip_tmp);
  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_AGEN);

  vex_encode (b, &xe);

  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_ADD);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, tmp);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

  xed_encoder_request_set_memory_operand_length (&xe, 8);
  xed_encoder_request_set_mem0 (&xe);
  xed_encoder_request_set_seg0 (&xe, XED_REG_FS);
  xed_encoder_request_set_memory_displacement (&xe, VEX_CTX_FSBASE, 4);
  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_MEM0);

  vex_encode (b, &xe);

  vex_encode_restore_rflags (b);
  vex_encode_restore_gpr (b, XED_REG_RSP);
}

static unsigned
save_inst (const unsigned char *p, char *buf, int size, size_t page, int *len)
{
  int i;

  char *b = buf;

  eri_assert (size >= 2 * sizeof p + 2);
  unsigned long t = (unsigned long) p;
  for (i = 0; i < 2 * sizeof p; ++i)
    {
      b[2 * sizeof p - i - 1] = eri_itoc (t % 16);
      t /= 16;
    }
  b[2 * sizeof p] = ':';
  b[2 * sizeof p + 1]  = ' ';
  b += 2 * sizeof p + 2;
  size -= 2 * sizeof p + 2;

  eri_assert (size >= 3 * XED_MAX_INSTRUCTION_BYTES);
  char *hex = b;
  b += 3 * XED_MAX_INSTRUCTION_BYTES;
  size -= 3 * XED_MAX_INSTRUCTION_BYTES;

  xed_decoded_inst_t xd;
  vex_decode ((unsigned long) p, page, &xd);

  eri_assert (xed_format_context (XED_SYNTAX_ATT, &xd, b, size, (xed_uint64_t) p, 0, 0));
  *len = (b - buf) + eri_strlen (b);
  xed_uint_t inst_len = xed_decoded_inst_get_length (&xd);

  for (i = 0; i < XED_MAX_INSTRUCTION_BYTES; ++i)
    {
      if (i < inst_len)
	{
	  hex[i * 3] = eri_itoc (p[i] / 16);
	  hex[i * 3 + 1] = eri_itoc (p[i] % 16);
	}
      else
	{
	  hex[i * 3] = ' ';
	  hex[i * 3 + 1] = ' ';
	}
      hex[i * 3 + 2] = ' ';
    }

  return inst_len;
}

static void
save_translated (struct vex *v,
		 unsigned long (*map)[2], int nmap,
		 const struct encode_buf *b)
{
  if (nmap == 0) return;

  int fd = eri_open_path (v->path, "vex-trans-", ERI_OPEN_WITHID, map[0][0]);
  size_t page = v->pagesize;

  int i = 0;
  size_t off = 0;
  int l;
  char buf[256];
  while (off != b->off)
    {
      if (i < nmap && off == map[i][1])
	{
	  buf[0] = ' ';
	  save_inst ((const unsigned char *) map[i][0],
		     buf + 1, sizeof buf - 1, page, &l);
	  eri_assert (l < sizeof buf - 1);
	  buf[l + 1] = '\n';
	  eri_assert (eri_fwrite (fd, buf, l + 2) == 0);
	  ++i;
	}

      buf[0] = buf[1] = buf[2] = ' ';
      unsigned len = save_inst ((const unsigned char *) b->p + off,
				buf + 3, sizeof buf - 3, page, &l);
      eri_assert (l < sizeof buf - 3);
      buf[l + 3] = '\n';
      eri_assert (eri_fwrite (fd, buf, l + 4) == 0);
      off += len;
    }
  eri_assert (i == nmap);
  eri_assert (eri_fclose (fd) == 0);

#if 0
  int cfd = eri_open_path (v->path, "vex-trans-bin-", ERI_OPEN_WITHID, map[0][0]);
  eri_assert (eri_fwrite (cfd, (const char *) b->p, b->off) == 0);
  eri_assert (eri_fclose (cfd) == 0);
#endif
}

#define vex_assert_common_regs(reg) \
  do {									\
    xed_reg_enum_t __reg = reg;						\
    eri_assert (__reg != XED_REG_FSBASE					\
		&& __reg != XED_REG_GSBASE				\
		&& (__reg < XED_REG_CS || __reg > XED_REG_GS));		\
  } while (0)

#define vex_mark_used_reg(regs, reg) \
  do {									\
    unsigned short *__regs = &(regs);					\
    xed_reg_enum_t __reg = xed_get_largest_enclosing_register (reg);	\
    if (__reg >= XED_REG_RAX && __reg <= XED_REG_R15)			\
      *__regs |= 1 << (__reg - XED_REG_RAX);				\
  } while (0)

static xed_reg_enum_t
vex_get_tmp_reg (struct encode_buf *b, unsigned short *used)
{
  unsigned short z = 0;
  if (! used) used = &z;

  int ffs = __builtin_ffs (~*used) - 1;
  eri_assert (ffs >= 0);
  xed_reg_enum_t tmp = XED_REG_RAX + ffs;
  cprintf (b->log, "*** used: %lu, tmp: %s\n", *used, xed_reg_enum_t2str (tmp));
  vex_mark_used_reg (*used, tmp);
  vex_encode_save_gpr (b, tmp);
  return tmp;
}

static xed_reg_enum_t
vex_get_rip_tmp (struct encode_buf *b, unsigned short *used,
		 unsigned long rip)
{
  xed_reg_enum_t tmp = vex_get_tmp_reg (b, used);
  vex_encode_set_rip_tmp (b, tmp, rip);
  return tmp;
}

static void *
vex_translate (int log, struct vex *v, unsigned long rip, unsigned long *inst_rips)
{
  unsigned long map[v->max_inst_count][2];

  size_t inst_size = eri_round_up (XED_MAX_INSTRUCTION_BYTES, 16);
  size_t size = eri_min (32, v->max_inst_count) * inst_size;
  struct encode_buf b = {
    log, &v->epool, size, eri_assert_mtmalloc (&v->epool, size)
  };

  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  char branch = 0;
  int i;
  for (i = 0; ! branch && i < v->max_inst_count; ++i)
    {
      cprintf (log, "decode %lx\n", rip);
      inst_rips[i] = rip;

      map[i][0] = rip;
      map[i][1] = b.off;

      xed_decoded_inst_t xd;
      vex_decode (rip, v->pagesize, &xd);

      xed_uint_t length = xed_decoded_inst_get_length (&xd);
      rip += length;

      const xed_inst_t *xi = xed_decoded_inst_inst (&xd);

      xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum (&xd);
      xed_iclass_enum_t iclass = xed_iform_to_iclass (iform);

      if (iclass == XED_ICLASS_SYSCALL || vex_is_transfer (iclass))
        vex_dump_inst (log, rip, &xd);

      eri_assert (iclass != XED_ICLASS_BOUND);
      eri_assert (iclass != XED_ICLASS_INT);
      eri_assert (iclass != XED_ICLASS_INT1);
      eri_assert (iclass != XED_ICLASS_INT3);
      eri_assert (iclass != XED_ICLASS_INTO);
      eri_assert (iclass != XED_ICLASS_IRET);

      eri_assert (iclass != XED_ICLASS_JMP_FAR);
      eri_assert (iclass != XED_ICLASS_CALL_FAR);
      eri_assert (iclass != XED_ICLASS_RET_FAR);

      xed_uint8_t noperands = xed_inst_noperands (xi);
      unsigned short regs = 0;
      char ref_fs = 0, ref_rip = 0, has_mem0_exp = 0, has_relbr = 0;

      int j;
      for (j = 0; j < noperands; ++j)
	{
	  /* e.g. movq	%rax,%fs:mem */
	  const xed_operand_t *op = xed_inst_operand (xi, j);
	  xed_operand_enum_t op_name = xed_operand_name (op);

	  eri_assert (op_name != XED_OPERAND_SEG0);
	  eri_assert (op_name != XED_OPERAND_SEG1);
	  eri_assert (op_name != XED_OPERAND_INDEX);
	  eri_assert (op_name != XED_OPERAND_OUTREG);

	  if (op_name == XED_OPERAND_BASE0
	      || op_name == XED_OPERAND_BASE1
	      || (op_name >= XED_OPERAND_REG0 && op_name <= XED_OPERAND_REG8))
	    {
	      xed_reg_enum_t reg = xed_decoded_inst_get_reg (&xd, op_name);
	      vex_assert_common_regs (reg);
	      vex_mark_used_reg (regs, reg);
	    }
	  else if (op_name == XED_OPERAND_MEM0 || op_name == XED_OPERAND_AGEN)
	    {
	      xed_reg_enum_t base = xed_decoded_inst_get_base_reg (&xd, 0);
	      xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg (&xd, 0);
	      xed_reg_enum_t index = xed_decoded_inst_get_index_reg (&xd, 0);

	      vex_assert_common_regs (base);
	      eri_assert (seg == XED_REG_INVALID
			  || (seg >= XED_REG_CS && seg <= XED_REG_FS));
	      vex_assert_common_regs (index);
	      eri_assert (index != XED_REG_RIP);

	      vex_mark_used_reg (regs, base);
	      vex_mark_used_reg (regs, index);

	      if (seg == XED_REG_FS)
		{
		  eri_assert (op_name != XED_OPERAND_AGEN);
		  eri_assert (! xed_operand_values_has_real_rep (&xd));
		  ref_fs = 1;
		}

	      ref_rip |= base == XED_REG_RIP;
	      has_mem0_exp |= op_name == XED_OPERAND_MEM0
			      && xed_operand_operand_visibility (op) == XED_OPVIS_EXPLICIT;
	    }
	  else if (op_name == XED_OPERAND_MEM1)
	    {
	      xed_reg_enum_t base = xed_decoded_inst_get_base_reg (&xd, 1);
	      xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg (&xd, 1);
	      vex_assert_common_regs (base);
	      eri_assert (base != XED_REG_RIP);
	      eri_assert (seg == XED_REG_INVALID
			  || (seg >= XED_REG_CS && seg <= XED_REG_SS));
	    }
	  else if (op_name == XED_OPERAND_RELBR)
	    has_relbr = 1;
	  else
	    eri_assert (op_name == XED_OPERAND_IMM0
			|| op_name == XED_OPERAND_IMM1
			|| op_name == XED_OPERAND_RELBR);
	}

      if (iclass == XED_ICLASS_SYSCALL)
	{
	  eri_assert (! ref_fs && ! ref_rip);

	  vex_encode_set_rip_tmp (&b, XED_REG_R11, rip);
	  vex_encode_save_rip (&b, XED_REG_R11);

	  vex_encode_jmp (&b, VEX_CTX_SYSCALL);
	  branch = 1;
	}
      else if (vex_is_transfer (iclass))
	{
	  xed_reg_enum_t tmp = vex_get_tmp_reg (&b, &regs);
	  if ((iclass == XED_ICLASS_JMP || iclass == XED_ICLASS_CALL_NEAR)
	      && ! has_relbr)
	    {
	      xed_reg_enum_t rip_tmp = XED_REG_INVALID;
	      if (iclass == XED_ICLASS_CALL_NEAR)
		{
		  if (ref_rip)
		    rip_tmp = vex_get_rip_tmp (&b, &regs, rip);
		  else
		    vex_encode_set_rip_tmp (&b, tmp, rip);
		  vex_encode_push_reg (&b, rip_tmp != XED_REG_INVALID ? rip_tmp : tmp);
		}
	      else if (ref_rip)
		rip_tmp = vex_get_rip_tmp (&b, &regs, rip);

	      if (ref_fs)
		{
		  /* e.g. jmp	*%fs:(%rax) */
		  vex_encode_calc_fsbased_mem (&b, &xd, tmp, rip_tmp);

		  /* movq	(%tmp), %tmp */
		  xed_encoder_request_t xe;
		  xed_encoder_request_zero_set_mode (&xe, &state);

		  xed_encoder_request_set_iclass (&xe, XED_ICLASS_MOV);
		  xed_encoder_request_set_effective_operand_width (&xe, 64);

		  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, tmp);
		  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

		  xed_encoder_request_set_memory_operand_length (&xe, 8);
		  xed_encoder_request_set_mem0 (&xe);
		  xed_encoder_request_set_base0 (&xe, tmp);
		  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_MEM0);

		  vex_encode (&b, &xe);
		}
	      else
		{
		  /* e.g. jmp	*(%eax)
		     =>   movq	(%eax), %tmp
		  */
		  xed_encoder_request_t xe;
		  xed_encoder_request_zero_set_mode (&xe, &state);

		  xed_encoder_request_set_iclass (&xe, XED_ICLASS_MOV);
		  eri_assert (xed_operand_values_get_effective_operand_width (&xd) == 64);
		  xed_encoder_request_set_effective_operand_width (&xe, 64);

		  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, tmp);
		  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

		  if (has_mem0_exp)
		    {
		      xed_encoder_request_set_memory_operand_length (&xe, 8);
		      xed_encoder_request_set_mem0 (&xe);
		      vex_copy_mem0 (&xe, &xd, ~0, rip_tmp);
		      xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_MEM0);
		    }
		  else
		    {
		      xed_encoder_request_set_reg (
			&xe, XED_OPERAND_REG1,
			xed_decoded_inst_get_reg (&xd, XED_OPERAND_REG0));
		      xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_REG1);
		    }

		  vex_encode (&b, &xe);
		}

	      /* movq	%tmp, %fs:RIP */
	      vex_encode_save_rip (&b, tmp);
	      if (rip_tmp != XED_REG_INVALID)
		vex_encode_restore_gpr (&b, rip_tmp);
	    }
	  else if (iclass == XED_ICLASS_RET_NEAR)
	    {
	      xed_reg_enum_t tmp = vex_get_tmp_reg (&b, &regs);
	      /*
		 popq	%tmp
		 movq	%tmp, %fs:RIP
		 movq	%fs:TMP, %tmp
		 leaq	imm16(%rsp), %rsp
	      */
	      xed_encoder_request_t xe;
	      xed_encoder_request_zero_set_mode (&xe, &state);

	      xed_encoder_request_set_iclass (&xe, XED_ICLASS_POP);
	      xed_encoder_request_set_effective_operand_width (&xe, 64);

	      xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, tmp);
	      xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

	      vex_encode (&b, &xe);

	      vex_encode_save_rip (&b, tmp);

	      xed_uint64_t uimm = xed_decoded_inst_get_unsigned_immediate (&xd);
	      if (uimm != 0)
		vex_encode_lea_disp (&b, XED_REG_RSP, uimm);
	    }
	  else
	    {
	      eri_assert (has_relbr);

	      xed_int32_t disp = xed_decoded_inst_get_branch_displacement (&xd);

	      if (iclass == XED_ICLASS_JMP)
		{
		  vex_encode_set_rip_tmp (&b, tmp, rip + disp);
		  vex_encode_save_rip (&b, tmp);
		}
	      else if (iclass == XED_ICLASS_CALL_NEAR)
		{
		  vex_encode_set_rip_tmp (&b, tmp, rip);
		  vex_encode_push_reg (&b, tmp);
		  vex_encode_lea_disp (&b, tmp, disp);
		  vex_encode_save_rip (&b, tmp);
		}
	      else
		{
		  /*
			e.g. ja	1f
			movq	$rip, %tmp		; bnj // bjmp
			jmp	2f
		     1: movq	$rip + disp, %tmp	; bj
		     2: movq	%tmp, %fs:RIP
		  */
		  xed_uint8_t bnj_buf[2 * inst_size];
		  struct encode_buf bnj = { log, 0, sizeof bnj_buf, bnj_buf };

		  xed_uint8_t bj_buf[inst_size];
		  struct encode_buf bj = { log, 0, sizeof bj_buf, bj_buf };

		  /* bj */
		  vex_encode_set_rip_tmp (&bj, tmp, rip + disp);

		  /* bnj */
		  vex_encode_set_rip_tmp (&bnj, tmp, rip);

		  xed_encoder_request_t xe;
		  xed_encoder_request_zero_set_mode (&xe, &state);

		  xed_encoder_request_set_iclass (&xe, XED_ICLASS_JMP);
		  /* xed_encoder_request_set_effective_operand_width (&xe, 64); */

		  xed_encoder_request_set_relbr (&xe);
		  xed_encoder_request_set_branch_displacement (
		    &xe, bj.off, get_disp_nbytes (bj.off, A_D | A_B));
		  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_RELBR);

		  vex_encode (&bnj, &xe);

		  /* e.g. ja	1f */
		  xed_encoder_request_zero_set_mode (&xe, &state);

		  xed_encoder_request_set_iclass (&xe, iclass);

		  xed_encoder_request_set_relbr (&xe);
		  xed_encoder_request_set_branch_displacement (&xe, bnj.off, 1);
		  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_RELBR);

		  vex_encode (&b, &xe);

		  vex_concat (&b, &bnj);
		  vex_concat (&b, &bj);

		  vex_encode_save_rip (&b, tmp);
		}
	    }
	  vex_encode_restore_gpr (&b, tmp);
	  vex_encode_jmp (&b, VEX_CTX_BACK);
	  branch = 1;
	}
      else if (ref_fs || ref_rip)
	{
	  xed_reg_enum_t rip_tmp = XED_REG_INVALID;
	  if (ref_rip)
	    rip_tmp = vex_get_rip_tmp (&b, &regs, rip);

	  if (ref_fs)
	    {
	      xed_reg_enum_t tmp = vex_get_tmp_reg (&b, &regs);
	      vex_encode_calc_fsbased_mem (&b, &xd, tmp, rip_tmp);

	      /*
		 e.g. movq	%rax, (%tmp)
	      */

	      xed_encoder_request_init_from_decode (&xd);
	      xed_encoder_request_set_seg0 (&xd, XED_REG_INVALID);
	      xed_encoder_request_set_base0 (&xd, tmp);
	      xed_encoder_request_set_index (&xd, XED_REG_INVALID);
	      xed_encoder_request_set_memory_displacement (&xd, 0, 0);

	      vex_encode (&b, &xd);

	      vex_encode_restore_gpr (&b, tmp);
	    }
	  else
	    {
	      xed_encoder_request_init_from_decode (&xd);
	      xed_encoder_request_set_base0 (&xd, rip_tmp);
	      vex_encode (&b, &xd);
	    }

	  if (rip_tmp != XED_REG_INVALID)
	    vex_encode_restore_gpr (&b, rip_tmp);
	}
      else
	{
	  xed_encoder_request_init_from_decode (&xd);
	  vex_encode (&b, &xd);
	}

#if 0
      int j;
      for (j = 0; j < xed_inst_noperands (xi); ++j)
	{
	  const xed_operand_t *op = xed_inst_operand (xi, j);
	  xed_operand_enum_t op_name = xed_operand_name (op);
	  if (op_name == XED_OPERAND_MEM0
	      || op_name == XED_OPERAND_MEM1)
	    {
	      xed_operand_action_enum_t action = xed_decoded_inst_operand_action (&xd, j);

	      if (action == XED_OPERAND_ACTION_RW
		  || action == XED_OPERAND_ACTION_R
		  || action == XED_OPERAND_ACTION_RCW
		  || action == XED_OPERAND_ACTION_CRW
		  || action == XED_OPERAND_ACTION_CR)
		{
		}

	      if (action == XED_OPERAND_ACTION_RW
		  || action == XED_OPERAND_ACTION_W
		  || action == XED_OPERAND_ACTION_RCW
		  || action == XED_OPERAND_ACTION_CW
		  || action == XED_OPERAND_ACTION_CRW)
		{
		}
	    }
	}
#endif
    }

  if (! branch)
    {
      xed_reg_enum_t tmp = vex_get_rip_tmp (&b, 0, rip);
      vex_encode_save_rip (&b, tmp);
      vex_encode_restore_gpr (&b, tmp);
      vex_encode_jmp (&b, VEX_CTX_BACK);
    }

  if (i != v->max_inst_count) inst_rips[i] = 0;
  save_translated (v, map, i, &b);
  return b.p;
}

static struct entry *
vex_get_entry (int log, struct vex *v, unsigned long rip)
{
  eri_lock (&v->entrys_lock, 1);
  struct entry *e = entry_rbt_get (v, &rip, ERI_RBT_EQ);
  if (! e)
    {
      e = eri_assert_mtcalloc (&v->pool, sizeof *e);
      e->rip = rip;
      entry_rbt_insert (v, e);
    }
  ++e->refs;
  /* TODO release lru  */
  eri_unlock (&v->entrys_lock, 1);

  if (! __atomic_load_n (&e->insts, __ATOMIC_ACQUIRE))
    {
      eri_lock (&e->trans_lock, 1);
      if (! e->insts)
	{
	  e->inst_rips = eri_assert_mtmalloc (
	    &v->pool, sizeof (unsigned long) * v->max_inst_count);
	  __atomic_store_n (&e->insts, vex_translate (log, v, rip, e->inst_rips),
			    __ATOMIC_RELEASE);
	}
      eri_unlock (&e->trans_lock, 1);
    }
  return e;
}

asm ("  .text						\n\
  .align 16						\n\
  .type vex_dispatch, @function				\n\
vex_dispatch:						\n\
  .cfi_startproc					\n\
  movq	%fs:" TOP ", %rsp				\n\
  call	vex_loop					\n\
  .cfi_undefined %rip					\n\
  .cfi_endproc						\n\
  .size vex_dispatch, .-vex_dispatch			\n\
  .previous						\n"
);

/* static */ void vex_dispatch (struct context *c);

static void __attribute__ ((used))
vex_loop (struct context *c)
{
  struct vex *v = c->vex;
  while (1)
    {
      cprintf (c->log, "get_entry %lx\n", c->ctx.comm.rip);
      struct entry *e = vex_get_entry (c->log, v, c->ctx.comm.rip);
      c->ctx.insts = (unsigned long) e->insts;

      if (__atomic_load_n (&v->group_exiting, __ATOMIC_RELAXED))
	VEX_EXIT_ALT_STACK (c, VEX_EXIT_WAIT, 0, 0);

      /* ERI_ASSERT_SYSCALL (exit, 0); */
      cprintf (c->log, "execute rip: %lx "
		       "rax: %lx, rcx: %lx, rdx: %lx, rbx: %lx "
		       "rsp: %lx, rbp: %lx, rsi: %lx, rdi: %lx "
		       "r8: %lx, r9: %lx, r10: %lx, r11: %lx "
		       "r12: %lx, r13: %lx, r14: %lx, r15: %lx\n",
		       c->ctx.comm.rip,
		       c->ctx.comm.rax, c->ctx.comm.rcx,
		       c->ctx.comm.rdx, c->ctx.comm.rbx,
		       c->ctx.comm.rsp, c->ctx.comm.rbp,
		       c->ctx.comm.rsi, c->ctx.comm.rdi,
		       c->ctx.comm.r8, c->ctx.comm.r9,
		       c->ctx.comm.r10, c->ctx.comm.r11,
		       c->ctx.comm.r12, c->ctx.comm.r13,
		       c->ctx.comm.r14, c->ctx.comm.r15);
      int i;
      for (i = 0; e->inst_rips[i] && i < v->max_inst_count; ++i)
	cprintf (c->log, ">>>> 0x%lx\n", e->inst_rips[i]);

      vex_execute ();

      __atomic_sub_fetch (&e->refs, 1, __ATOMIC_RELEASE);
    }
  eri_assert (0);
}

static void
monitor_pool_malloc (struct eri_pool *pool, size_t size,
		     int res, void *p, void *name)
{
#if 0
  if (res == 0)
    eri_assert (eri_printf ("%s: %lu\n", name, pool->used) == 0);
#endif
}

static void
monitor_pool_free (struct eri_pool *pool,
		   void *p, int res, void *name)
{
#if 0
  if (res == 0)
    eri_assert (eri_printf ("%s: %lu\n", name, pool->used) == 0);
#endif
}


static void
setup_pool_monitor (struct eri_pool *pool, const char *name)
{
  pool->cb_malloc = monitor_pool_malloc;
  pool->cb_free = monitor_pool_free;
  pool->cb_data = (void *) name;
}

void
eri_vex_enter (char *buf, size_t size,
	       const struct eri_vex_context *ctx,
	       const char *path, char mmap)
{
  size_t page = ctx->pagesize;
  eri_assert (size >= 8 * 1024);
  struct vex *v = (struct vex *) buf;
  eri_memset (v, 0, sizeof *v);
  v->pagesize = page;
  v->path = path;

  if (mmap)
    {
      v->mmap = buf;
      v->mmap_size = size;
    }

  buf += 8 * 1024;
  size -= 8 * 1024;
  v->exit_stack_top = buf;

  eri_assert ((unsigned long) buf % page == 0 && size % page == 0);
  size_t psize = size / page / 2 * page;
  eri_assert (eri_init_pool (&v->pool.pool, buf, psize) == 0);
  setup_pool_monitor (&v->pool.pool, "pool");

  char *ebuf = buf + psize;
  size_t esize = size - psize;
  eri_assert (eri_init_pool (&v->epool.pool, ebuf, esize) == 0);
  setup_pool_monitor (&v->epool.pool, "epool");

  ERI_ASSERT_SYSCALL (mprotect, ebuf, esize, 0x7);

  v->max_inst_count = 256;

  struct context *c = alloc_context (v);
  eri_memcpy (&c->ctx.comm, &ctx->comm, sizeof c->ctx.comm);

  __atomic_add_fetch (&v->ncontexts, 1, __ATOMIC_ACQUIRE);
  start_context (c);

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_FS, c);

  xed_register_abort_function (vex_xed_abort, 0);
  xed_tables_init ();

  vex_dispatch (c);
}

/* For xed.  */

void *
memset (void *s, int c, size_t n)
{
  eri_memset (s, (char) c, n);
  return s;
}

void *
memcpy (void *d, const void *s, size_t n)
{
  eri_memcpy (d, s, n);
  return d;
}

int
memcmp (const void *s1, const void *s2, size_t n)
{
  return eri_memcmp (s1, s2, n);
}

size_t
strlen (const char *s)
{
  return eri_strlen (s);
}

char *
strncat (char *d, const char *s, size_t n)
{
  eri_strncat (d, s, n);
  return d;
}

int
strcmp (const char *s1, const char *s2)
{
  return eri_strcmp (s1, s2);
}

void abort (void) { while (1) continue; }
int fprintf (void *a1, void *a2, ...) { return 0; }
void *stderr;
