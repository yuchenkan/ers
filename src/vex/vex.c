#include <stdarg.h>
#include <asm/unistd.h>

#include "vex-pub.h"

#include "vex.h"
#include "vex-offsets.h"

#include "common.h"

#include "lib/buf.h"
#include "lib/util.h"
#include "lib/util-common.h"
#include "lib/printf.h"
#include "lib/malloc.h"
#include "lib/rbtree.h"
#include "lib/list.h"
#include "lib/syscall.h"

#include "xed/xed-util.h"
#include "xed/xed-interface.h"

struct vex;
struct entry;

struct context
{
  struct vex_context ctx;

  void *mp;
  unsigned long id;

  struct vex *vex;
  struct entry *entry;

  void *stack;

  long sys_tid;

  struct context *child;

  eri_file_t log;
  eri_file_t rip_file;

  ERI_LST_NODE_FIELDS (context);
};

static void cprintf (eri_file_t log, const char *fmt, ...);

static void
vex_xed_abort (const char *msg, const char *file, int line, void *other)
{
  struct context *c;
  asm ("movq	%%fs:%c1, %0" : "=r" (c) : "i" (VEX_CTX_CTX));
  cprintf (c->log, "xed_abort[%s:%u]: %s\n", file, line, msg);
  eri_assert (0);
}

static void
vex_decode (unsigned long rip, size_t pagesize, char *dec_buf,
	    xed_decoded_inst_t *xd)
{
  eri_assert (! pagesize || pagesize >= XED_MAX_INSTRUCTION_BYTES - 1);

  xed_decoded_inst_zero (xd);
  xed_decoded_inst_set_mode (xd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  unsigned bytes = XED_MAX_INSTRUCTION_BYTES;
  if (pagesize)
    bytes = eri_min (eri_round_up (rip + 1, pagesize) - rip, bytes);

  const xed_uint8_t *it = dec_buf
			  ? (const xed_uint8_t *) dec_buf : (const xed_uint8_t *) rip;

  if (dec_buf) eri_memcpy (dec_buf, (void *) rip, bytes);
  xed_error_enum_t error = xed_decode (xd, it, bytes);

  if (bytes != XED_MAX_INSTRUCTION_BYTES
      && error == XED_ERROR_BUFFER_TOO_SHORT)
    {
      if (dec_buf)
	eri_memcpy (dec_buf + bytes, (void *) (rip + bytes),
		    XED_MAX_INSTRUCTION_BYTES - bytes);

      xed_decoded_inst_zero (xd);
      xed_decoded_inst_set_mode (xd, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
      error = xed_decode (xd, it, XED_MAX_INSTRUCTION_BYTES);
    }
  eri_assert (error == XED_ERROR_NONE);
}

static void
vex_dump_inst (eri_file_t log, unsigned long rip, const xed_decoded_inst_t *xd)
{
  xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum (xd);
  cprintf (log, "iclass: %u %s,",
	   xed_iform_to_iclass (iform),
	   xed_iform_to_iclass_string_att (iform));

  xed_uint_t length = xed_decoded_inst_get_length (xd);
  xed_uint32_t eow = xed_operand_values_get_effective_operand_width (xd);
  xed_uint32_t eaw = xed_operand_values_get_effective_address_width (xd);

  const xed_inst_t *xi = xed_decoded_inst_inst (xd);
  int noperands = xed_inst_noperands (xi);
  cprintf (log, "length: %u, eow: %u, eaw: %u, noperands: %u\n",
	   length, eow, eaw, noperands);

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

      xed_operand_action_enum_t rw = xed_decoded_inst_operand_action (xd, idx);
      cprintf (log, "action: %s\n", xed_operand_action_enum_t2str (rw));
    }
}

struct inst_rip
{
  unsigned long rip;
  char rep;
};

struct entry
{
  unsigned long rip;
  ERI_RBT_NODE_FIELDS (entry, struct entry)

  int trans_lock;
  struct inst_rip *inst_rips;
  size_t length;
  void *insts;
  void *decoded_insts;

  unsigned long max_nreads;
  unsigned long max_nwrites;

  unsigned refs;
};

struct pool_monitor
{
  const char *name;
  size_t peek;
};

struct vex
{
  size_t pagesize;
  const char *path;
  size_t stack_size;
  size_t file_buf_size;

  char detail;

  eri_vex_proc_break_t brk;
  unsigned long brk_mask;
  void *brk_data;

  void *mmap;
  size_t mmap_size;
  char group_exiting;

  int exit_stack_lock;
  void *exit_stack_top;

  int entrys_lock;
  ERI_RBT_TREE_FIELDS (entry, struct entry)

  unsigned long context_id;
  unsigned ncontexts;
  int contexts_lock;
  ERI_LST_LIST_FIELDS (context);

  struct pool_monitor pool_monitor;
  struct pool_monitor epool_monitor;

  struct eri_mtpool pool;
  struct eri_mtpool epool;

  int max_inst_count;

  long sys_pid;
};

ERI_DEFINE_RBTREE (static, entry, struct vex, struct entry, unsigned long, eri_less_than)
ERI_DEFINE_LIST (static, context, struct vex, struct context)

/* static */ void vex_syscall (void);
/* static */ void vex_back (void);

static void
cprintf (eri_file_t log, const char *fmt, ...)
{
  if (! log) return;

  va_list arg;
  va_start (arg, fmt);
  eri_assert (eri_vfprintf (log, fmt, arg) == 0);
  va_end (arg);
};

static struct context *
alloc_context (struct vex *v)
{
  __atomic_add_fetch (&v->ncontexts, 1, __ATOMIC_ACQUIRE);
  size_t esize = eri_round_up (sizeof (struct context) + 48, 16);
  size_t size = esize + v->stack_size + 2 * v->file_buf_size;

  void *p;
  struct context *c = (struct context *) eri_round_up (
      (unsigned long) (p = eri_assert_mtcalloc (&v->pool, size)),
      64);
  c->mp = p;
  c->ctx.ctx = c;
  c->id = __atomic_fetch_add (&v->context_id, 1, __ATOMIC_RELAXED);

  c->ctx.syscall = (unsigned long) vex_syscall;
  c->ctx.back = (unsigned long) vex_back;
  c->stack = (char *) c->mp + esize;
  c->ctx.top = (unsigned long) c->stack + v->stack_size;

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
  size_t buf_size = v->file_buf_size;

  c->log = eri_open_path (v->path, "vex-log-", ERI_OPEN_WITHID, c->id,
    (char *) c->stack + v->stack_size, buf_size);
  c->rip_file = eri_open_path (v->path, "vex-rip-", ERI_OPEN_WITHID, c->id,
    (char *) c->stack + v->stack_size + buf_size, buf_size);

  c->sys_tid = ERI_ASSERT_SYSCALL_RES (gettid);

  eri_lock (&v->contexts_lock);
  context_lst_append (v, c);
  eri_unlock (&v->contexts_lock);

  if (v->detail)
    cprintf (c->log, "context: %lu, stack: %lx\n", c->id, c->stack);
}

static void
free_context (struct context *c)
{
  struct vex *v = c->vex;
  eri_assert_mtfree (&c->vex->pool, c->mp);
  __atomic_add_fetch (&v->ncontexts, -1, __ATOMIC_RELEASE);
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
  start_context (c);
  vex_loop (c);
}

static void
init_rw_ranges (struct eri_mtpool *p, struct vex_rw_ranges *rw, size_t n)
{
  rw->naddrs = rw->nsizes = 0;
  rw->addrs = n ? eri_assert_mtmalloc (p, n * sizeof (unsigned long) * 2) : 0;
  rw->sizes = rw->addrs ? rw->addrs + n : 0;
}

static void
vex_break (struct vex *v, struct context *c, unsigned long type)
{
  eri_assert (v);
  eri_assert (c->ctx.reads.naddrs == c->ctx.reads.nsizes);
  eri_assert (c->ctx.writes.naddrs == c->ctx.writes.nsizes);

  if (! v->brk || ! (v->brk_mask & type)) return;

  char post = type == ERI_VEX_BRK_POST_EXEC
	      || type & ERI_VEX_BRK_EXIT_MASK;

  struct eri_vex_brk_desc d = {
    &c->ctx.comm, c->entry->rip, c->entry->length, 0, 0, type,
    &v->pool, v->brk_data
  };

  if (post)
    {
      struct eri_vex_rw_ranges r = {
	c->ctx.reads.naddrs, c->ctx.reads.addrs, c->ctx.reads.sizes
      };

      struct eri_vex_rw_ranges w = {
	c->ctx.writes.naddrs, c->ctx.writes.addrs, c->ctx.writes.sizes
      };

      d.reads = &r;
      d.writes = &w;

      v->brk (&d);

      if (c->ctx.reads.addrs)
	eri_assert_mtfree (&v->pool, c->ctx.reads.addrs);
      if (c->ctx.writes.addrs)
	eri_assert_mtfree (&v->pool, c->ctx.writes.addrs);
    }
  else v->brk (&d);

#if 0
  size_t i;
  for (i = 0; i < c->ctx.reads.naddrs; ++i)
    cprintf (c->log, "read %lx, %lu\n",
	     c->ctx.reads.addrs[i], c->ctx.reads.sizes[i]);
  for (i = 0; i < c->ctx.writes.naddrs; ++i)
    cprintf (c->log, "write %lx, %lu\n",
	     c->ctx.writes.addrs[i], c->ctx.writes.sizes[i]);
#endif
}

#define VEX_EXIT_GROUP	0
#define VEX_EXIT_WAIT	1
#define VEX_EXIT_SELF	2

static void __attribute__ ((used))
vex_exit_alt_stack (int type, unsigned long status, int nr, struct context *c)
{
  cprintf (c->log, "exit %u\n", type);

  struct vex *v = c->vex;

  eri_lock (&v->contexts_lock);
  context_lst_remove (c);
  eri_unlock (&v->contexts_lock);

  eri_assert (eri_fclose (c->log) == 0);
  eri_assert (eri_fclose (c->rip_file) == 0);
  /* The thread stack can now be freed.  */
  free_context (c);

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
    eri_lock (&__v->exit_stack_lock);							\
    asm ("movq	%q0, %%rsp\n\t"								\
	 "movl	%1, %%edi\n\t"								\
	 "movq	%q2, %%rsi\n\t"								\
	 "movl	%3, %%edx\n\t"								\
	 "movq	%q4, %%rcx\n\t"								\
	 "call	vex_exit_alt_stack"							\
	 : : "r" (__v->exit_stack_top), "r" (type), "r" (status), "r" (nr), "r" (__c)	\
	 : "rsp", "rdi", "rsi", "rdx", "rcx");						\
  } while (0)

#define SIGINTR ERI_SIGURG

static void __attribute__ ((used))
vex_exit (unsigned long status, int nr, struct context *ctx)
{
  struct vex *v = ctx->vex;

  int type;
  char grp = nr == __NR_exit_group || ctx->id == 0;

  if (grp)
    {
      if (__atomic_exchange_n (&v->group_exiting, 1, __ATOMIC_ACQ_REL) == 0)
	{
	  eri_lock (&v->contexts_lock);
	  struct context *c;
	  ERI_LST_FOREACH (context, v, c)
	    if (c != ctx)
	      ERI_ASSERT_SYSCALL (tgkill, v->sys_pid, c->sys_tid, SIGINTR);
	  eri_unlock (&v->contexts_lock);

	  while (__atomic_load_n (&v->ncontexts, __ATOMIC_ACQUIRE) != 1)
	    continue;

	  vex_break (v, ctx, ERI_VEX_BRK_EXIT_GROUP);

	  struct entry *e, *ne;
	  ERI_RBT_FOREACH_SAFE (entry, v, e, ne)
	    {
	      entry_rbt_remove (v, e);
	      eri_assert (eri_free (&v->epool.pool, e->decoded_insts) == 0);
	      eri_assert (eri_free (&v->pool.pool, e) == 0);
	    }

	  eri_assert (eri_printf ("vex epool used: %lu\n", v->epool.pool.used) == 0);
	  eri_assert (eri_fini_pool (&v->epool.pool) == 0);

	  type = VEX_EXIT_GROUP;
	}
      else
	{
	  vex_break (v, ctx, ERI_VEX_BRK_EXIT_WAIT);

	  /* Exiting is already started by another context.  */
	  type = VEX_EXIT_WAIT;
	}
    }
  else
    {
      vex_break (v, ctx, ERI_VEX_BRK_EXIT);
      type = VEX_EXIT_SELF;
    }

  VEX_EXIT_ALT_STACK (ctx, type, status, nr);
}

#define CTX	_ERS_STR (VEX_CTX_CTX)

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

#define INTR	_ERS_STR (VEX_CTX_INTR)
#define ISKIP	_ERS_STR (VEX_CTX_ISKIP)

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

static struct eri_sigset sig_block;
static struct eri_sigset sig_unblock __attribute__ ((used));

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
  cmpl	$" _ERS_STR (__NR_futex) ", %eax		\n\
  je	.futex						\n\
  cmpl	$" _ERS_STR (__NR_rt_sigaction) ", %eax		\n\
  je	.assert_failed					\n\
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
  leaq	1f(%rip), %r11					\n\
  movq	%r11, %fs:" RET "				\n\
  jmp	vex_back					\n\
1:							\n\
  movl	%fs:" RAX ", %esi				\n\
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
.futex:							\n\
  movq	%rsi, %fs:" RSI "				\n\
  andq	$" _ERS_STR (ERI_FUTEX_CMD_MASK) ", %rsi	\n\
  cmpq	$" _ERS_STR (ERI_FUTEX_WAIT) ", %rsi		\n\
  je	1f						\n\
  cmpq	$" _ERS_STR (ERI_FUTEX_WAIT_BITSET) ", %rsi	\n\
1:							\n\
  movq	%fs:" RSI ", %rsi				\n\
  je	.intr						\n\
  jmp	.syscall					\n\
							\n\
.intr:							\n\
  movq	%rax, %fs:" RAX "				\n\
  leaq	1f(%rip), %rax					\n\
  xchg	%fs:" RET ", %rax				\n\
  movq	%rax, %fs:" INTR "				\n\
  movq	%fs:" RAX", %rax				\n\
  jmp	vex_back					\n\
1:							\n\
  movq	%fs:" INTR ", %rax				\n\
  movq	%rax, %fs:" RET "				\n\
  leaq	1f(%rip), %rax					\n\
  movq	%rax, %fs:" INTR "				\n\
  leaq	2f(%rip), %rax					\n\
  movq	%rax, %fs:" ISKIP "				\n\
							\n\
  movl	$" _ERS_STR (__NR_rt_sigprocmask) ", %eax	\n\
  movq	$" _ERS_STR (ERI_SIG_SETMASK) ", %rdi		\n\
  leaq	sig_unblock(%rip), %rsi				\n\
  movq	$0, %rdx					\n\
  movq	$" _ERS_STR (ERI_SIG_SETSIZE)", %r10		\n\
  syscall						\n\
  cmpq	$-4095, %rax					\n\
  jae	.assert_failed					\n\
							\n\
  movq	%fs:" RAX ", %rax				\n\
  movq	%fs:" RDI ", %rdi				\n\
  movq	%fs:" RSI ", %rsi				\n\
  movq	%fs:" RDX ", %rdx				\n\
  movq	%fs:" R10 ", %r10				\n\
  syscall						\n\
1:							\n\
  movq	%rax, %fs:" RAX "				\n\
2:							\n\
							\n\
  movl	$" _ERS_STR (__NR_rt_sigprocmask) ", %eax	\n\
  movq	$" _ERS_STR (ERI_SIG_SETMASK) ", %rdi		\n\
  leaq	sig_block(%rip), %rsi				\n\
  movq	$0, %rdx					\n\
  movq	$" _ERS_STR (ERI_SIG_SETSIZE)", %r10		\n\
  syscall						\n\
  cmpq	$-4095, %rax					\n\
  jae	.assert_failed					\n\
  jmp	*%fs:" RET "					\n\
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
  eri_file_t log;

  struct eri_buf buf;
};

static void
vex_encode (struct encode_buf *buf, xed_encoder_request_t *xe)
{
  xed_uint8_t b[XED_MAX_INSTRUCTION_BYTES];
  unsigned int l;
  xed_error_enum_t error = xed_encode (xe, b,
				       XED_MAX_INSTRUCTION_BYTES, &l);
  if (error != XED_ERROR_NONE)
    {
      cprintf (buf->log, "encode error: %s\n", xed_error_enum_t2str (error));
      eri_assert (0);
    }

  /* Reserve one instruction length, so decoding (e.g. dumping generated
     instructions) won't pass the end of the buffer.  */
  eri_buf_reserve (&buf->buf, XED_MAX_INSTRUCTION_BYTES);
  eri_buf_append (&buf->buf, b, l);
}

static void
vex_concat (struct encode_buf *b1, const struct encode_buf *b2)
{
  /* Reserve one instruction length, so decoding (e.g. dumping generated
     instructions) won't pass the end of the buffer.  */
  eri_buf_reserve (&b1->buf, b2->buf.off + XED_MAX_INSTRUCTION_BYTES);
  eri_buf_concat (&b1->buf, &b2->buf);
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

struct mem
{
  xed_operand_enum_t op_name;

  xed_reg_enum_t base;
  xed_reg_enum_t index;
  xed_uint_t scale;
  xed_int64_t disp;
  xed_uint_t disp_width;
  xed_reg_enum_t seg;

  unsigned int length;
  xed_operand_visibility_enum_t vis;
  xed_operand_action_enum_t rw;
};

static void
vex_xed_set_mem0 (xed_encoder_request_t *xe, struct mem *m)
{
  if (m->op_name == XED_OPERAND_MEM0)
    xed_encoder_request_set_mem0 (xe);
  else if (m->op_name == XED_OPERAND_AGEN)
    xed_encoder_request_set_agen (xe);
  else eri_assert (0);

  xed_encoder_request_set_seg0 (xe, m->seg);
  xed_encoder_request_set_base0 (xe, m->base);
  xed_encoder_request_set_index (xe, m->index);
  xed_encoder_request_set_scale (xe, m->scale);
  xed_encoder_request_set_memory_displacement (xe, m->disp, m->disp_width);
}

#define REG_DISP(r) (VEX_CTX_RAX + (r) * 8)

static void
ctx_encode_mov_reg (struct encode_buf *b,
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
ctx_encode_save_gpr (struct encode_buf *b, xed_reg_enum_t reg)
{
  /* movq	%reg, %fs:REG */
  ctx_encode_mov_reg (b, reg, 1, REG_DISP (reg - XED_REG_RAX));
}

static void
ctx_encode_restore_gpr (struct encode_buf *b, xed_reg_enum_t reg)
{
  /* movq	%fs:REG, %reg */
  ctx_encode_mov_reg (b, reg, 0, REG_DISP (reg - XED_REG_RAX));
}

static void
ctx_encode_save_rip (struct encode_buf *b, xed_reg_enum_t reg)
{
  /* movq	%reg, %fs:RIP */
  ctx_encode_mov_reg (b, reg, 1, VEX_CTX_RIP);
}

static void
ctx_encode_switch_to_internal_stack (struct encode_buf *b)
{
  /*
     movq	%rsp, %fs:RSP
     movq	%fs:TOP, %rsp
  */
  ctx_encode_save_gpr (b, XED_REG_RSP);
  ctx_encode_mov_reg (b, XED_REG_RSP, 0, VEX_CTX_TOP);
}

static void
ctx_encode_save_rflags (struct encode_buf *b)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;

  /*
     pushfq
     popq	%fs:RFLAGS
  */
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
ctx_encode_push (struct encode_buf *b, long offset)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;

  /* pushq	%fs:offset */
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
ctx_encode_restore_rflags (struct encode_buf *b)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;

  /*
     pushq	%fs:RFLAGS
     popfq
  */

  ctx_encode_push (b, VEX_CTX_RFLAGS);

  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_POPFQ);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  vex_encode (b, &xe);
}

static void
vex_encode_set_reg_imm (struct encode_buf *b, xed_reg_enum_t reg,
			unsigned long imm)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;

  /* movq	$imm, %reg */
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_MOV);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, reg);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

  xed_encoder_request_set_uimm0 (&xe, imm,
				 get_uimm_nbytes (imm, A_D | A_Q));
  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_IMM0);

  vex_encode (b, &xe);
}

static void
vex_encode_push_reg (struct encode_buf *b, xed_reg_enum_t reg)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;

  /* pushq	%reg */
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

  xed_encoder_request_t xe;

  /* leaq	disp(%reg), %reg */
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
vex_encode_lea_mem (struct encode_buf *b, struct mem *m,
		    xed_reg_enum_t reg)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;

  /* leaq	m, %reg */
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_LEA);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, reg);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

  vex_xed_set_mem0 (&xe, m);
  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_AGEN);

  vex_encode (b, &xe);
}

static void
ctx_encode_jmp (struct encode_buf *b, size_t offset)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;

  /* jmp	*%fs:offset */
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

static void
vex_encode_jmp_relbr (struct encode_buf *b, xed_iclass_enum_t iclass,
		      xed_int64_t rel)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;

  /* jmp	$rel */
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, iclass);
  /* xed_encoder_request_set_effective_operand_width (&xe, 64); */

  xed_encoder_request_set_relbr (&xe);
  xed_encoder_request_set_branch_displacement (&xe, rel, get_disp_nbytes (rel, A_D | A_B));
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_RELBR);

  vex_encode (b, &xe);
}

static unsigned
save_inst (const unsigned char *p, char *buf, int size, int *len)
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
  vex_decode ((unsigned long) p, 0, 0, &xd);

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
save_translated (const char *path, unsigned long rip,
		 unsigned long (*map)[2], int nmap,
		 const struct encode_buf *b)
{
  eri_file_buf_t file_buf[32 * 1024];
  eri_file_t file = eri_open_path (path, "vex-trans-", ERI_OPEN_WITHID,
				   rip, file_buf, sizeof file_buf);

  int i = 0;
  size_t off = 0;
  int l;
  char buf[256];
  while (off != b->buf.off)
    {
      if (i < nmap && off == map[i][1])
	{
	  buf[0] = ' ';
	  save_inst ((const unsigned char *) (rip + map[i][0] - map[0][0]),
		     buf + 1, sizeof buf - 1, &l);
	  eri_assert (l < sizeof buf - 1);
	  buf[l + 1] = '\n';
	  eri_assert (eri_fwrite (file, buf, l + 2, 0) == 0);
	  ++i;
	}

      buf[0] = buf[1] = buf[2] = ' ';
      unsigned len = save_inst ((const unsigned char *) b->buf.buf + off,
				buf + 3, sizeof buf - 3, &l);
      eri_assert (l < sizeof buf - 3);
      buf[l + 3] = '\n';
      eri_assert (eri_fwrite (file, buf, l + 4, 0) == 0);
      off += len;
    }
  eri_assert (i == nmap);
  eri_assert (eri_fclose (file) == 0);

#if 0
  int cfd = eri_open_path (v->path, "vex-trans-bin-", ERI_OPEN_WITHID, map[0][0]);
  eri_assert (eri_fwrite (cfd, (const char *) b->p, b->off, 0) == 0);
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
  vex_mark_used_reg (*used, tmp);
  ctx_encode_save_gpr (b, tmp);
  return tmp;
}

#define REC_MEM_OP_NREGS	3

static void
vex_encode_mov_reg_mem (struct encode_buf *b, xed_reg_enum_t reg, struct mem *m,
			char reg_to_mem)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_MOV);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, reg);
  xed_encoder_request_set_operand_order (&xe, reg_to_mem, XED_OPERAND_REG0);

  xed_encoder_request_set_memory_operand_length (&xe, 8);
  vex_xed_set_mem0 (&xe, m);
  xed_encoder_request_set_operand_order (&xe, ! reg_to_mem, XED_OPERAND_MEM0);

  vex_encode (b, &xe);
}

static void
vex_encode_mov_reg_to_mem (struct encode_buf *b, xed_reg_enum_t reg, struct mem *m)
{
  /* movq	%reg, mem */
  vex_encode_mov_reg_mem (b, reg, m, 1);
}

static void
vex_encode_mov_mem_to_reg (struct encode_buf *b, struct mem *m, xed_reg_enum_t reg)
{
  /* movq	mem, reg */
  vex_encode_mov_reg_mem (b, reg, m, 0);
}

static void
vex_encode_mov_reg_to_bis (struct encode_buf *b, xed_reg_enum_t reg,
			   xed_reg_enum_t base, xed_reg_enum_t index, xed_uint_t scale)
{
  struct mem m = { XED_OPERAND_MEM0, base, index, scale };
  vex_encode_mov_reg_to_mem (b, reg, &m);
}

static void
vex_encode_mov_bis_to_reg (struct encode_buf *b, xed_reg_enum_t base,
			   xed_reg_enum_t index, xed_uint_t scale, xed_reg_enum_t reg)
{
  struct mem m = { XED_OPERAND_MEM0, base, index, scale };
  vex_encode_mov_mem_to_reg (b, &m, reg);
}

static void
ctx_record_mem_operand_rw_addr (struct encode_buf *b, struct mem *m,
				size_t off, xed_reg_enum_t *tmps)
{
  /*
     movq	%fs:NADDRS, %tmp1
     movq	%fs:ADDRS, %tmp2
     leaq	mem, %tmp3
     movq	%tmp3, (%tmp2, %tmp1, 8)
     leaq	1(%tmp1), %tmp1
     movq	%tmp1, %fs:NADDRS
  */

  xed_operand_enum_t op_name = m->op_name;
  m->op_name = XED_OPERAND_AGEN;

  ctx_encode_mov_reg (b, tmps[0], 0, off + VEX_RW_RANGES_NADDRS);
  ctx_encode_mov_reg (b, tmps[1], 0, off + VEX_RW_RANGES_ADDRS);
  vex_encode_lea_mem (b, m, tmps[2]);
  vex_encode_mov_reg_to_bis (b, tmps[2], tmps[1], tmps[0], sizeof (unsigned long));
  vex_encode_lea_disp (b, tmps[0], 1);
  ctx_encode_mov_reg (b, tmps[0], 1, off + VEX_RW_RANGES_NADDRS);

  m->op_name = op_name;
}

#define inst_size (eri_round_up (XED_MAX_INSTRUCTION_BYTES, 16))

static void
ctx_record_mem_operand_rw_size (struct encode_buf *b, struct mem *m,
				char rep, size_t off, xed_reg_enum_t *tmps)
{
  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;
  if (! rep)
    {
      /*
	 movq	%fs:NSIZES, %tmp1
	 movq	%fs:SIZES, %tmp2
	 movq	$length, (%tmp2, %tmp1, 8)
	 leaq	1(%tmp1), %tmp1
	 movq	%tmp1, %fs:NSIZES
      */

      ctx_encode_mov_reg (b, tmps[0], 0, off + VEX_RW_RANGES_NSIZES);
      ctx_encode_mov_reg (b, tmps[1], 0, off + VEX_RW_RANGES_SIZES);

      xed_encoder_request_zero_set_mode (&xe, &state);

      xed_encoder_request_set_iclass (&xe, XED_ICLASS_MOV);
      xed_encoder_request_set_effective_operand_width (&xe, 64);

      xed_encoder_request_set_memory_operand_length (&xe, 8);
      xed_encoder_request_set_mem0 (&xe);
      xed_encoder_request_set_base0 (&xe, tmps[1]);
      xed_encoder_request_set_index (&xe, tmps[0]);
      xed_encoder_request_set_scale (&xe, sizeof (unsigned long));
      xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_MEM0);

      xed_encoder_request_set_uimm0 (&xe, m->length, 4);
      xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_IMM0);

      vex_encode (b, &xe);

      vex_encode_lea_disp (b, tmps[0], 1);
      ctx_encode_mov_reg (b, tmps[0], 1, off + VEX_RW_RANGES_NSIZES);
    }
  else
    {
      ctx_encode_switch_to_internal_stack (b);
      ctx_encode_save_rflags (b);

      /*
	 sizes[nsizes] = mem - addrs[nsizes];
	 if (sizes[nsizes] < 0)
	   {
	     sizes[nsizes] = -sizes[nsizes];
	     addrs[nsizes] = mem + length;
	   }
	 ++nsizes;

	    movq	%fs:NSIZES, %tmp1		; begin
	    movq	%fs:ADDRS, %tmp2
	    movq	(%tmp2, %tmp1, 8), %tmp3
	    leaq	mem, %tmp2
	    subq	%tmp3, %tmp2			; mem - addrs[nsizes]
	    movq	%fs:SIZES, %tmp3
	    jl	1f
	    movq	%tmp2, (%tmp3, %tmp1, 8)	; bnd, direction flag not set
	    jmp	2f
	 1: negq	%tmp2				; bd, direction flag set
	    movq	%tmp2, (%tmp3, %tmp1, 8)
	    movq	%fs:ADDRS, %tmp2
	    leaq	mem, %tmp3
	    leaq	length(%tmp3), %tmp3
	    movq	%tmp3, (%tmp2, %tmp1, 8)
	 2: leaq	1(%tmp1), %tmp1			; inc size
	    movq	%tmp1, %fs:NSIZES
      */

      xed_operand_enum_t op_name = m->op_name;
      m->op_name = XED_OPERAND_AGEN;

      xed_uint8_t bnd_buf[2 * inst_size];
      struct encode_buf bnd = { b->log };
      eri_buf_static_init (&bnd.buf, bnd_buf, sizeof bnd_buf);

      xed_uint8_t bd_buf[6 * inst_size];
      struct encode_buf bd = { b->log };
      eri_buf_static_init (&bd.buf, bd_buf, sizeof bd_buf);

      /* bd */
      xed_encoder_request_zero_set_mode (&xe, &state);

      xed_encoder_request_set_iclass (&xe, XED_ICLASS_NEG);
      xed_encoder_request_set_effective_operand_width (&xe, 64);

      xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, tmps[1]);
      xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

      vex_encode (&bd, &xe);

      vex_encode_mov_reg_to_bis (&bd, tmps[1], tmps[2], tmps[0], sizeof (unsigned long));
      ctx_encode_mov_reg (&bd, tmps[1], 0, off + VEX_RW_RANGES_ADDRS);
      vex_encode_lea_mem (&bd, m, tmps[2]);
      vex_encode_lea_disp (&bd, tmps[2], m->length);
      vex_encode_mov_reg_to_bis (&bd, tmps[2], tmps[1], tmps[0], sizeof (unsigned long));

      /* bnd */
      vex_encode_mov_reg_to_bis (&bnd, tmps[1], tmps[2], tmps[0], sizeof (unsigned long));
      vex_encode_jmp_relbr (&bnd, XED_ICLASS_JMP, bd.buf.off);

      /* begin */
      ctx_encode_mov_reg (b, tmps[0], 0, off + VEX_RW_RANGES_NSIZES);
      ctx_encode_mov_reg (b, tmps[1], 0, off + VEX_RW_RANGES_ADDRS);
      vex_encode_mov_bis_to_reg (b, tmps[1], tmps[0], sizeof (unsigned long), tmps[2]);
      vex_encode_lea_mem (b, m, tmps[1]);

      xed_encoder_request_zero_set_mode (&xe, &state);

      xed_encoder_request_set_iclass (&xe, XED_ICLASS_SUB);
      xed_encoder_request_set_effective_operand_width (&xe, 64);

      xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, tmps[1]);
      xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

      xed_encoder_request_set_reg (&xe, XED_OPERAND_REG1, tmps[2]);
      xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_REG1);

      vex_encode (b, &xe);

      ctx_encode_mov_reg (b, tmps[2], 0, off + VEX_RW_RANGES_SIZES);
      vex_encode_jmp_relbr (b, XED_ICLASS_JL, bnd.buf.off);

      vex_concat (b, &bnd);
      vex_concat (b, &bd);

      /* inc size */
      vex_encode_lea_disp (b, tmps[0], 1);
      ctx_encode_mov_reg (b, tmps[0], 1, off + VEX_RW_RANGES_NSIZES);

      m->op_name = op_name;

      ctx_encode_restore_rflags (b);
      ctx_encode_restore_gpr (b, XED_REG_RSP);
    }
}

static void
ctx_record_mem_operand_addr (struct encode_buf *b, struct mem *m,
			     xed_reg_enum_t *tmps, struct entry *e)
{
  if (xed_operand_action_read (m->rw))
    {
      ++e->max_nreads;
      ctx_record_mem_operand_rw_addr (b, m, VEX_CTX_READS, tmps);
    }

  if (xed_operand_action_written (m->rw))
    {
      ++e->max_nwrites;
      ctx_record_mem_operand_rw_addr (b, m, VEX_CTX_WRITES, tmps);
    }
}

static void
ctx_record_mem_operand_size (struct encode_buf *b, struct mem *m,
			     char rep, xed_reg_enum_t *tmps)
{
  if (xed_operand_action_read (m->rw))
    ctx_record_mem_operand_rw_size (b, m, rep, VEX_CTX_READS, tmps);
  if (xed_operand_action_written (m->rw))
    ctx_record_mem_operand_rw_size (b, m, rep, VEX_CTX_WRITES, tmps);
}

static void
ctx_record_mem_operands_addr (struct encode_buf *b, struct mem *m, size_t n,
			      unsigned short *used, xed_reg_enum_t *tmps,
			      struct entry *e)
{
  vex_mark_used_reg (*used, XED_REG_RSP);

  size_t i;
  for (i = 0; i < REC_MEM_OP_NREGS; ++i)
    tmps[i] = vex_get_tmp_reg (b, used);

  for (i = 0; i < n; ++i)
    if (m->op_name != XED_OPERAND_INVALID && m->op_name != XED_OPERAND_AGEN)
      ctx_record_mem_operand_addr (b, m + i, tmps, e);
}

static void
ctx_record_mem_operands_size (struct encode_buf *b, struct mem *m, size_t n,
			      char rep, xed_reg_enum_t *tmps)
{
  size_t i;
  for (i = 0; i < n; ++i)
    if (m->op_name != XED_OPERAND_INVALID && m->op_name != XED_OPERAND_AGEN)
      ctx_record_mem_operand_size (b, m + i, rep, tmps);

  for (i = 0; i < REC_MEM_OP_NREGS; ++i)
    ctx_encode_restore_gpr (b, tmps[i]);
}

static void *
vex_translate (eri_file_t log, struct vex *v, struct entry *e)
{
  unsigned long map[v->max_inst_count][2];

  size_t size = eri_min (32, v->max_inst_count) * inst_size;
  struct encode_buf b = { log };
  eri_buf_mtpool_init (&b.buf, &v->epool, size);

  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  xed_encoder_request_t xe;

  unsigned long rip = e->rip;
  eri_assert (e->length == 0);
  eri_assert (e->max_nreads == 0);
  eri_assert (e->max_nwrites == 0);

  int i = 0;
  while (1)
    {
      char *dec_buf = (char *) e->insts + e->length;

      if (v->detail) cprintf (log, "decode %lx\n", rip);

      xed_decoded_inst_t xd;
      vex_decode (rip, v->pagesize, dec_buf, &xd);

      map[i][0] = (unsigned long) dec_buf;
      map[i][1] = b.buf.off;

      e->inst_rips[i].rip = rip;
      e->inst_rips[i].rep = xed_operand_values_has_real_rep (&xd);

      xed_uint_t length = xed_decoded_inst_get_length (&xd);
      rip += length;
      e->length += length;

      const xed_inst_t *xi = xed_decoded_inst_inst (&xd);

      xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum (&xd);
      xed_iclass_enum_t iclass = xed_iform_to_iclass (iform);

      char dmp = v->detail
		 && (iclass == XED_ICLASS_SYSCALL || vex_is_transfer (iclass));
      vex_dump_inst (dmp ? log : 0, rip, &xd);

      eri_assert (iclass != XED_ICLASS_BOUND);
      eri_assert (iclass != XED_ICLASS_INT);
      eri_assert (iclass != XED_ICLASS_INT1);
      eri_assert (iclass != XED_ICLASS_INT3);
      eri_assert (iclass != XED_ICLASS_INTO);
      eri_assert (iclass != XED_ICLASS_IRET);

      eri_assert (iclass != XED_ICLASS_JMP_FAR);
      eri_assert (iclass != XED_ICLASS_CALL_FAR);
      eri_assert (iclass != XED_ICLASS_RET_FAR);

      char rep = xed_operand_values_has_real_rep (&xd);
      xed_uint8_t noperands = xed_inst_noperands (xi);
      unsigned short regs = 0;
      char relbr = 0;
      struct mem m[] = { { XED_OPERAND_INVALID }, { XED_OPERAND_INVALID } };

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
	      eri_assert (m[0].op_name == XED_OPERAND_INVALID);
	      m[0].op_name = op_name;

	      m[0].base = xed_decoded_inst_get_base_reg (&xd, 0);
	      m[0].seg = xed_decoded_inst_get_seg_reg (&xd, 0);
	      m[0].index = xed_decoded_inst_get_index_reg (&xd, 0);

	      m[0].scale = xed_decoded_inst_get_scale (&xd, 0);
	      m[0].disp = xed_decoded_inst_get_memory_displacement (&xd, 0);
	      m[0].disp_width = xed_decoded_inst_get_memory_displacement_width (&xd, 0);

	      m[0].length = xed_decoded_inst_get_memory_operand_length (&xd, 0);
	      m[0].vis = xed_operand_operand_visibility (op);
	      m[0].rw = xed_decoded_inst_operand_action (&xd, j);

	      vex_mark_used_reg (regs, m[0].base);
	      vex_mark_used_reg (regs, m[0].index);
	    }
	  else if (op_name == XED_OPERAND_MEM1)
	    {
	      eri_assert (m[1].op_name == XED_OPERAND_INVALID);
	      m[1].op_name = op_name;

	      m[1].base = xed_decoded_inst_get_base_reg (&xd, 1);
	      m[1].seg = xed_decoded_inst_get_seg_reg (&xd, 1);

	      m[1].length = xed_decoded_inst_get_memory_operand_length (&xd, 0);

	      vex_assert_common_regs (m[1].base);
	      eri_assert (m[1].base != XED_REG_RIP);
	      eri_assert (m[1].seg == XED_REG_INVALID
			  || (m[1].seg >= XED_REG_CS && m[1].seg <= XED_REG_SS));
	    }
	  else if (op_name == XED_OPERAND_RELBR)
	    relbr = 1;
	  else
	    eri_assert (op_name == XED_OPERAND_IMM0
			|| op_name == XED_OPERAND_IMM1
			|| op_name == XED_OPERAND_RELBR);
	}

      xed_reg_enum_t mem0_tmp = XED_REG_INVALID;
      if (m[0].op_name != XED_OPERAND_INVALID)
	{
	  vex_assert_common_regs (m[0].base);
	  eri_assert (m[0].seg == XED_REG_INVALID
		      || (m[0].seg >= XED_REG_CS && m[0].seg <= XED_REG_FS));
	  vex_assert_common_regs (m[0].index);
	  eri_assert (m[0].index != XED_REG_RIP);

	  char ref_rip = m[0].base == XED_REG_RIP;
	  char ref_fs = m[0].seg == XED_REG_FS && m[0].op_name == XED_OPERAND_MEM0;

	  if (ref_rip || ref_fs)
	    {
	      eri_assert (m[0].vis != XED_OPVIS_SUPPRESSED);
	      eri_assert (m[0].vis != XED_OPVIS_IMPLICIT);
	      mem0_tmp = vex_get_tmp_reg (&b, &regs);
	    }

	  if (ref_rip)
	    {
	      vex_encode_set_reg_imm (&b, mem0_tmp, rip);
	      m[0].base = mem0_tmp;
	    }

	  if (ref_fs)
	    {
	      eri_assert (! rep);

	      ctx_encode_switch_to_internal_stack (&b);
	      ctx_encode_save_rflags (&b);

	      /*
		 leaq	mem0, %mem0_tmp
		 addq	%fs:FSBASE, %mem0_tmp
	      */

	      m[0].op_name = XED_OPERAND_AGEN;
	      m[0].seg = XED_REG_INVALID;

	      vex_encode_lea_mem (&b, m, mem0_tmp);

	      xed_encoder_request_zero_set_mode (&xe, &state);

	      xed_encoder_request_set_iclass (&xe, XED_ICLASS_ADD);
	      xed_encoder_request_set_effective_operand_width (&xe, 64);

	      xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, mem0_tmp);
	      xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

	      xed_encoder_request_set_memory_operand_length (&xe, 8);
	      xed_encoder_request_set_mem0 (&xe);
	      xed_encoder_request_set_seg0 (&xe, XED_REG_FS);
	      xed_encoder_request_set_memory_displacement (&xe, VEX_CTX_FSBASE, 4);
	      xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_MEM0);

	      vex_encode (&b, &xe);

	      ctx_encode_restore_rflags (&b);
	      ctx_encode_restore_gpr (&b, XED_REG_RSP);

	      m[0].op_name = XED_OPERAND_MEM0;
	      m[0].seg = XED_REG_INVALID;
	      m[0].base = mem0_tmp;
	      m[0].index = XED_REG_INVALID;
	      m[0].scale = 0;
	      m[0].disp = 0;
	      m[0].disp_width = 0;
	    }
	}

      char rec = v->brk
		 && (m[0].op_name == XED_OPERAND_MEM0
		     || m[1].op_name == XED_OPERAND_MEM1);
      xed_reg_enum_t rec_mem_tmps[REC_MEM_OP_NREGS];
      if (rec)
	{
	  ctx_record_mem_operands_addr (&b, m, 2, &regs, rec_mem_tmps, e);

	  if (! rep)
	    ctx_record_mem_operands_size (&b, m, 2, rep, rec_mem_tmps);
	}

      ++i;
      if (iclass == XED_ICLASS_SYSCALL)
	{
	  eri_assert (! rep);
	  eri_assert (mem0_tmp == XED_REG_INVALID);

	  vex_encode_set_reg_imm (&b, XED_REG_R11, rip);
	  ctx_encode_save_rip (&b, XED_REG_R11);

	  ctx_encode_jmp (&b, VEX_CTX_SYSCALL);
	  break;
	}
      else if (vex_is_transfer (iclass))
	{
	  eri_assert (! rep);

	  xed_reg_enum_t rip_tmp = vex_get_tmp_reg (&b, &regs);
	  if (iclass == XED_ICLASS_RET_NEAR)
	    {
	      eri_assert (mem0_tmp == XED_REG_INVALID);
	      /*
		 popq	%rip_tmp
		 movq	%rip_tmp, %fs:RIP
		 leaq	imm16(%rsp), %rsp
	      */
	      xed_encoder_request_t xe;
	      xed_encoder_request_zero_set_mode (&xe, &state);

	      xed_encoder_request_set_iclass (&xe, XED_ICLASS_POP);
	      xed_encoder_request_set_effective_operand_width (&xe, 64);

	      xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, rip_tmp);
	      xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

	      vex_encode (&b, &xe);

	      xed_uint64_t uimm = xed_decoded_inst_get_unsigned_immediate (&xd);
	      if (uimm != 0)
		vex_encode_lea_disp (&b, XED_REG_RSP, uimm);
	    }
	  else if (relbr)
	    {
	      eri_assert (mem0_tmp == XED_REG_INVALID);

	      xed_int32_t disp = xed_decoded_inst_get_branch_displacement (&xd);

	      if (iclass == XED_ICLASS_CALL_NEAR)
		{
		  vex_encode_set_reg_imm (&b, rip_tmp, rip);
		  vex_encode_push_reg (&b, rip_tmp);

		  vex_encode_lea_disp (&b, rip_tmp, disp);
		}
	      else if (iclass == XED_ICLASS_JMP)
		vex_encode_set_reg_imm (&b, rip_tmp, rip + disp);
	      else
		{
		  /*
			e.g. ja	1f
			movq	$rip, %rip_tmp		; bnj, no conditional jump
			jmp	2f
		     1: movq	$rip + disp, %rip_tmp	; bj, conditional jump
		     2:
		  */
		  xed_uint8_t bnj_buf[2 * inst_size];
		  struct encode_buf bnj = { log };
		  eri_buf_static_init (&bnj.buf, bnj_buf, sizeof bnj_buf);

		  xed_uint8_t bj_buf[inst_size];
		  struct encode_buf bj = { log };
		  eri_buf_static_init (&bj.buf, bj_buf, sizeof bj_buf);

		  /* bj */
		  vex_encode_set_reg_imm (&bj, rip_tmp, rip + disp);

		  /* bnj */
		  vex_encode_set_reg_imm (&bnj, rip_tmp, rip);
		  vex_encode_jmp_relbr (&bnj, XED_ICLASS_JMP, bj.buf.off);

		  /* e.g. ja	1f */
		  xed_encoder_request_zero_set_mode (&xe, &state);

		  xed_encoder_request_set_iclass (&xe, iclass);

		  xed_encoder_request_set_relbr (&xe);
		  xed_encoder_request_set_branch_displacement (&xe, bnj.buf.off, 1);
		  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_RELBR);

		  vex_encode (&b, &xe);

		  vex_concat (&b, &bnj);
		  vex_concat (&b, &bj);
		}
	    }
	  else
	    {
	      eri_assert (iclass == XED_ICLASS_JMP || iclass == XED_ICLASS_CALL_NEAR);

	      if (iclass == XED_ICLASS_CALL_NEAR)
		{
		  vex_encode_set_reg_imm (&b, rip_tmp, rip);
		  vex_encode_push_reg (&b, rip_tmp);
		}

	      xed_encoder_request_zero_set_mode (&xe, &state);

	      xed_encoder_request_set_iclass (&xe, XED_ICLASS_MOV);
	      eri_assert (xed_operand_values_get_effective_operand_width (&xd) == 64);
	      xed_encoder_request_set_effective_operand_width (&xe, 64);

	      xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, rip_tmp);
	      xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

	      if (m[0].op_name == XED_OPERAND_MEM0
		  && (m[0].vis == XED_OPVIS_EXPLICIT || m[0].vis == XED_OPVIS_IMPLICIT))
		{
		  eri_assert (m[0].vis != XED_OPVIS_IMPLICIT);

		  xed_encoder_request_set_memory_operand_length (&xe, 8);
		  vex_xed_set_mem0 (&xe, m);
		  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_MEM0);
		}
	      else
		{
		  xed_reg_enum_t reg = xed_decoded_inst_get_reg (&xd, XED_OPERAND_REG0);
		  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG1, reg);
		  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_REG1);
		}

	      vex_encode (&b, &xe);
	    }

	  ctx_encode_save_rip (&b, rip_tmp);
	  ctx_encode_restore_gpr (&b, rip_tmp);

	  if (mem0_tmp != XED_REG_INVALID) ctx_encode_restore_gpr (&b, mem0_tmp);

	  ctx_encode_jmp (&b, VEX_CTX_BACK);
	  break;
	}
      else
	{
	  xed_encoder_request_init_from_decode (&xd);
	  if (m[0].op_name != XED_OPERAND_INVALID) vex_xed_set_mem0 (&xd, m);
	  vex_encode (&b, &xd);

	  if (rec && rep)
	    ctx_record_mem_operands_size (&b, m, 2, rep, rec_mem_tmps);

	  if (i == v->max_inst_count)
	    {
	      xed_reg_enum_t rip_tmp = mem0_tmp != XED_REG_INVALID
				       ? mem0_tmp : vex_get_tmp_reg (&b, 0);
	      vex_encode_set_reg_imm (&b, rip_tmp, rip);
	      ctx_encode_save_rip (&b, rip_tmp);
	      ctx_encode_restore_gpr (&b, rip_tmp);
	      ctx_encode_jmp (&b, VEX_CTX_BACK);
	      break;
	    }

	  if (mem0_tmp != XED_REG_INVALID)
	    ctx_encode_restore_gpr (&b, mem0_tmp);
	}
    }

  if (i != v->max_inst_count) e->inst_rips[i].rip = 0;
  if (v->detail) save_translated (v->path, e->rip, map, i, &b);
  return b.buf.buf;
}

static struct entry *
vex_get_entry (eri_file_t log, struct vex *v, unsigned long rip)
{
  eri_lock (&v->entrys_lock);
  struct entry *e = entry_rbt_get (v, &rip, ERI_RBT_EQ);
  if (! e)
    {
      size_t esz = eri_size_of (*e, 16);
      size_t ripsz = sizeof e->inst_rips[0] * v->max_inst_count;
      e = eri_assert_mtcalloc (&v->pool,
	esz + ripsz + XED_MAX_INSTRUCTION_BYTES * v->max_inst_count);
      e->rip = rip;
      entry_rbt_insert (v, e);
      e->inst_rips = (struct inst_rip *) ((char *) e + esz);
      e->insts = (char *) e->inst_rips + ripsz;
    }
  ++e->refs;
  /* TODO release lru  */
  eri_unlock (&v->entrys_lock);

#if 0
  if (e->length
      && eri_memcmp ((void *) rip, e->insts, e->length) != 0)
    {
      eri_assert (e->decoded_insts);
      eri_assert_mtfree (&v->epool, e->decoded_insts);
      e->decoded_insts = 0;
      e->length = 0;
    }
#endif
  if (! __atomic_load_n (&e->decoded_insts, __ATOMIC_ACQUIRE))
    {
      eri_lock (&e->trans_lock);
      if (! e->decoded_insts)
	__atomic_store_n (&e->decoded_insts, vex_translate (log, v, e),
			  __ATOMIC_RELEASE);
      eri_unlock (&e->trans_lock);
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
      if (__atomic_load_n (&v->group_exiting, __ATOMIC_RELAXED))
	VEX_EXIT_ALT_STACK (c, VEX_EXIT_WAIT, 0, 0);

      if (v->detail) cprintf (c->log, "get_entry %lx\n", c->ctx.comm.rip);
      struct entry *e = c->entry = vex_get_entry (c->log, v, c->ctx.comm.rip);
      c->ctx.insts = (unsigned long) e->decoded_insts;

      /* ERI_ASSERT_SYSCALL (exit, 0); */
      if (v->detail)
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
      if (v->detail)
	for (i = 0; i < v->max_inst_count && e->inst_rips[i].rip; ++i)
	  {
	    cprintf (c->log,
		     e->inst_rips[i].rep ? ">>>> 0x%lx...\n" : ">>>> 0x%lx\n",
		     e->inst_rips[i].rip);
	    cprintf (c->rip_file,
		     e->inst_rips[i].rep ? "0x%lx...\n" : "0x%lx\n",
		     e->inst_rips[i].rip);
	  }
      else
	for (i = 0; i < v->max_inst_count && e->inst_rips[i].rip; ++i)
	  {
	    struct inst_rip *ir = e->inst_rips + i;
	    eri_assert (eri_fwrite (c->rip_file, (const char *) &ir->rip, sizeof ir->rip, 0) == 0);
	    eri_assert (eri_fwrite (c->rip_file, (const char *) &ir->rep, sizeof ir->rep, 0) == 0);
	  }

      if (v->brk)
	{
	  init_rw_ranges (&v->pool, &c->ctx.reads, e->max_nreads);
	  init_rw_ranges (&v->pool, &c->ctx.writes, e->max_nwrites);
	}

      vex_break (v, c, ERI_VEX_BRK_PRE_EXEC);

      vex_execute ();

      vex_break (v, c, ERI_VEX_BRK_POST_EXEC);

      __atomic_sub_fetch (&e->refs, 1, __ATOMIC_RELEASE);
    }
  eri_assert (0);
}

static void
monitor_pool_malloc (struct eri_pool *pool, size_t size,
		     int res, void *p, void *data)
{
  struct pool_monitor *monitor = data;
  if (res == 0 && pool->used > 2 * monitor->peek)
    {
      while (pool->used > 2 * monitor->peek) monitor->peek *= 2;
      eri_assert (eri_printf ("malloc %s: %lum\n",
			      monitor->name, pool->used / 1024 / 1024) == 0);
    }
}

static void
setup_pool_monitor (struct eri_pool *pool, struct pool_monitor *monitor, const char *name)
{
  monitor->name = name;
  monitor->peek = 1024 * 1024;

  pool->cb_malloc = monitor_pool_malloc;
  pool->cb_data = monitor;
}

asm ("  .text						\n\
  .align 16						\n\
  .type sigact, @function				\n\
sigact:							\n\
  movq	%fs:" INTR ", %rax				\n\
  cmpq	%rax, " _ERS_STR (ERI_UCONTEXT_RIP) "(%rdx)	\n\
  jb	1f						\n\
  ret							\n\
1:							\n\
  movq	%fs:" TOP ", %rsp				\n\
  movq	$-" _ERS_STR (ERI_EINTR) ", %fs:" RAX "		\n\
  jmp	*%fs:" ISKIP "					\n\
  .size sigact, .-sigact				\n\
  .previous						\n"
);

/* static */ void sigact (int signum, struct eri_siginfo *info, void *ucontext);

void
eri_vex_enter (const struct eri_vex_desc *desc)
{
  char *buf = desc->buf;
  size_t size = desc->size;

  size_t page = desc->pagesize;
  eri_assert (size >= 8 * 1024);
  struct vex *v = (struct vex *) buf;
  eri_memset (v, 0, sizeof *v);
  v->pagesize = page;
  v->path = desc->path;
  v->stack_size = 2 * 1024 * 1024;
#ifdef DEBUG
  v->detail = 1;
#else
  v->file_buf_size = 32 * 1024;
#endif

  v->brk = desc->brk;
  v->brk_mask = desc->brk_mask;
  v->brk_data = desc->brk_data;

  if (desc->mmap)
    {
      v->mmap = buf;
      v->mmap_size = size;
    }

  buf += 8 * 1024;
  size -= 8 * 1024;
  v->exit_stack_top = buf;

  eri_assert ((unsigned long) buf % page == 0 && size % page == 0);
  size_t psize = size - size / page / 8 * page;
  eri_assert (eri_init_pool (&v->pool.pool, buf, psize) == 0);
  setup_pool_monitor (&v->pool.pool, &v->pool_monitor, "pool");

  if (desc->pool) *desc->pool = &v->pool;

  char *ebuf = buf + psize;
  size_t esize = size - psize;
  eri_assert (eri_init_pool (&v->epool.pool, ebuf, esize) == 0);
  setup_pool_monitor (&v->epool.pool, &v->epool_monitor, "epool");

  ERI_ASSERT_SYSCALL (mprotect, ebuf, esize, 0x7);

  v->max_inst_count = 32;

  v->sys_pid = ERI_ASSERT_SYSCALL_RES (getpid);

  ERI_LST_INIT_LIST (context, v);

  struct context *c = alloc_context (v);
  eri_memcpy (&c->ctx.comm, &desc->comm, sizeof c->ctx.comm);

  start_context (c);

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_FS, c);

  eri_sigaddset (&sig_block, SIGINTR);

  ERI_ASSERT_SYSCALL (rt_sigprocmask, ERI_SIG_SETMASK, &sig_block, 0, ERI_SIG_SETSIZE);
  struct eri_sigaction a = { sigact, ERI_SA_RESTORER | ERI_SA_SIGINFO, eri_sigreturn };
  ERI_ASSERT_SYSCALL (rt_sigaction, SIGINTR, &a, 0, ERI_SIG_SETSIZE);

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
