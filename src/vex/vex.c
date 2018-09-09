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

static void
vex_xed_abort (const char *msg, const char *file, int line, void *other)
{
  eri_assert (eri_printf ("%s:%u: %s\n", file, line, msg) == 0);
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
vex_dump_inst (unsigned long rip, const xed_decoded_inst_t *xd)
{
  xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum (xd);
  eri_assert (eri_printf ("iclass: %u %s,",
			  xed_iform_to_iclass (iform),
			  xed_iform_to_iclass_string_att (iform)) == 0);

  xed_uint_t length = xed_decoded_inst_get_length (xd);
  xed_uint32_t eow = xed_operand_values_get_effective_operand_width (xd);

  const xed_inst_t *xi = xed_decoded_inst_inst (xd);
  int noperands = xed_inst_noperands (xi);
  eri_assert (eri_printf ("length: %u, eow: %u, noperands: %u\n",
			  length, eow, noperands) == 0);

  int i;
  for (i = 0; i < noperands; ++i)
    {
      int idx = noperands - i - 1;
      const xed_operand_t *op = xed_inst_operand (xi, idx);
      xed_operand_enum_t op_name = xed_operand_name (op);
      eri_assert (eri_printf ("  opname: %s, ", xed_operand_enum_t2str (op_name)) == 0);

      if (op_name == XED_OPERAND_SEG0
	  || op_name == XED_OPERAND_SEG1
	  || op_name == XED_OPERAND_INDEX
	  || op_name == XED_OPERAND_BASE0
	  || op_name == XED_OPERAND_BASE1
	  || (op_name >= XED_OPERAND_REG0 && op_name <= XED_OPERAND_REG8))
	{
	  xed_reg_enum_t reg = xed_decoded_inst_get_reg (xd, op_name);
	  eri_assert (eri_printf ("operand: %s, ", xed_reg_enum_t2str (reg)) == 0);
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

	  eri_assert (eri_printf ("base: %s, ", xed_reg_enum_t2str (base)) == 0);
	  eri_assert (eri_printf ("seg: %s, ", xed_reg_enum_t2str (seg)) == 0);
	  eri_assert (eri_printf ("index: %s, ", xed_reg_enum_t2str (index)) == 0);
	  eri_assert (eri_printf ("disp: %lx, %lx, ", disp, ~disp + 1) == 0);
	  eri_assert (eri_printf ("disp_bits: %u, ", disp_bits) == 0);
	  eri_assert (eri_printf ("bytes: %u, ", bytes) == 0);
	}
      else if (op_name == XED_OPERAND_MEM1)
	{
	  xed_reg_enum_t base = xed_decoded_inst_get_base_reg (xd, 1);
	  xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg (xd, 1);
	  xed_uint_t bytes = xed_decoded_inst_operand_length_bits (xd, idx) >> 3;

	  eri_assert (base != XED_REG_FSBASE && base != XED_REG_GSBASE);
	  eri_assert (seg != XED_REG_FSBASE && seg != XED_REG_GSBASE);

	  eri_assert (eri_printf ("base: %s, ", xed_reg_enum_t2str (base)) == 0);
	  eri_assert (eri_printf ("seg: %s, ", xed_reg_enum_t2str (seg)) == 0);
	  eri_assert (eri_printf ("bytes: %u, ", bytes) == 0);
	}
      else if (op_name == XED_OPERAND_RELBR)
	{
	  xed_int32_t disp = xed_decoded_inst_get_branch_displacement (xd);

	  eri_assert (eri_printf ("disp: %x, %x, ", disp, ~disp + 1) == 0);
	  eri_assert (eri_printf ("addr: %lx, ", rip + length + disp) == 0);
	}
      else if (op_name == XED_OPERAND_IMM0)
	{
	  xed_uint64_t imm = xed_decoded_inst_get_unsigned_immediate (xd);
	  xed_uint_t is_signed = xed_decoded_inst_get_immediate_is_signed (xd);
	  xed_uint_t bytes = xed_decoded_inst_get_immediate_width (xd);

	  eri_assert (eri_printf ("imm: %lx, %lu, %lx, %lu, ", imm, imm, ~imm + 1, ~imm + 1) == 0);
	  eri_assert (eri_printf ("is_signed: %u, ", is_signed) == 0);
	  eri_assert (eri_printf ("bytes: %u, ", bytes) == 0);
	}

      xed_operand_action_enum_t action = xed_decoded_inst_operand_action (xd, idx);
      eri_assert (eri_printf ("action: %s\n", xed_operand_action_enum_t2str (action)) == 0);
    }
}

struct entry
{
  unsigned long rip;
  ERI_RBT_NODE_FIELDS (entry, struct entry)

  int trans_lock;
  void *insts;

  unsigned refs;
};

struct context
{
  struct vex_context ctx;

  struct vex *vex;
  ERI_LST_NODE_FIELDS (context)

  void *stack;
};

struct vex
{
  size_t pagesize;
  const char *path;

  int entrys_lock;
  ERI_RBT_TREE_FIELDS (entry, struct entry)

  ERI_LST_LIST_FIELDS (context)

  struct eri_mtpool pool;
  struct eri_mtpool epool;

  int max_inst_count;
};

ERI_DEFINE_RBTREE (static, entry, struct vex, struct entry, unsigned long, eri_less_than)

ERI_DEFINE_LIST (static, context, struct vex, struct context)

#define RFLAGS	_ERS_STR (VEX_CTX_RFLAGS)
#define RAX	_ERS_STR (VEX_CTX_RAX)
#define RDI	_ERS_STR (VEX_CTX_RDI)
#define RSP	_ERS_STR (VEX_CTX_RSP)

#define FSBASE	_ERS_STR (VEX_CTX_FSBASE)

#define INSTS	_ERS_STR (VEX_CTX_INSTS)
#define RET	_ERS_STR (VEX_CTX_RET)
#define TOP	_ERS_STR (VEX_CTX_TOP)

asm ("  .text						\n\
  .align 16						\n\
  .type vex_syscall, @function				\n\
vex_syscall:						\n\
  cmpl	$" _ERS_STR (__NR_arch_prctl) ", %eax		\n\
  jne	2f						\n\
  cmpq	$" _ERS_STR (ERI_ARCH_SET_FS) ", %rdi		\n\
  jne	1f						\n\
  movq	%rsi, %fs:" FSBASE "				\n\
  xorq	%rax, %rax					\n\
  jmp	3f						\n\
1:							\n\
  cmpq	$" _ERS_STR (ERI_ARCH_GET_FS) ", %rdi		\n\
  jne	2f						\n\
  movq	%fs:" FSBASE ", %rax				\n\
  movq	%rax, (%rsi)					\n\
  xorq	%rax, %rax					\n\
  jmp	3f						\n\
2:							\n\
  syscall						\n\
3:							\n\
  ret							\n\
  .size vex_syscall, .-vex_syscall			\n\
  .previous						\n"
);

asm ("  .text						\n\
  .align 16						\n\
vex_back:						\n\
  movq	%rax, %fs:" RAX "				\n\
  movq	%rdi, %fs:" RDI "				\n\
  movq	%rsp, %fs:" RSP "				\n\
  movq	%fs:" TOP ", %rsp				\n\
  pushfq						\n\
  popq	%fs:" RFLAGS "					\n\
  pushq	%fs:" RET "					\n\
  ret							\n\
  .previous						\n"
);

/* static */ void vex_syscall (void);
/* static */ void vex_back (void);

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
  struct eri_mtpool *pool;

  size_t size;
  xed_uint8_t *p;
  size_t off;
};

static void
inc_encode_buf (struct encode_buf *b)
{
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
      eri_assert (eri_printf ("encode error: %s\n",
			      xed_error_enum_t2str (error)) == 0);
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
vex_get_disp_nbytes (long disp, int acc)
{
  if (acc & A_B && disp < 0x7f && disp >= -0x80) return 1;
  else if (acc & A_W && disp < 0x7fff && disp >= -0x8000) return 2;
  else if (acc & A_D && disp < 0x7fffffff && disp >= 0x80000000) return 4;
  else if (acc & A_Q) return 8;
  else eri_assert (0);
  return 0;
}

static void
vex_encode_inc_rip (struct encode_buf *b, xed_int32_t disp)
{
  vex_encode_switch_to_internal_stack (b);
  vex_encode_save_rflags (b);

  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  /* addq	$disp, %fs:RIP */
  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_ADD);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_memory_operand_length (&xe, 8);
  xed_encoder_request_set_mem0 (&xe);
  xed_encoder_request_set_seg0 (&xe, XED_REG_FS);
  xed_encoder_request_set_memory_displacement (&xe, VEX_CTX_RIP, 4);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_MEM0);

  xed_encoder_request_set_simm (
    &xe, disp, vex_get_disp_nbytes (disp, A_D | A_B));
  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_IMM0);

  vex_encode (b, &xe);

  vex_encode_restore_rflags (b);
  vex_encode_restore_gpr (b, XED_REG_RSP);
}

static void
vex_encode_push_rip (struct encode_buf *b)
{
  /* pushq	%fs:RIP */
  vex_encode_push (b, VEX_CTX_RIP);
}

static void
vex_encode_call (struct encode_buf *b, long offset)
{
  vex_encode_switch_to_internal_stack (b);

  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  /* call	*%fs:offset */
  xed_encoder_request_t xe;
  xed_encoder_request_zero_set_mode (&xe, &state);

  xed_encoder_request_set_iclass (&xe, XED_ICLASS_CALL_NEAR);
  xed_encoder_request_set_effective_operand_width (&xe, 64);

  xed_encoder_request_set_memory_operand_length (&xe, 8);
  xed_encoder_request_set_mem0 (&xe);
  xed_encoder_request_set_seg0 (&xe, XED_REG_FS);
  xed_encoder_request_set_memory_displacement (&xe, offset, 4);
  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_MEM0);

  vex_encode (b, &xe);

  vex_encode_restore_gpr (b, XED_REG_RSP);
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
	       int flags)
{
  if (flags & COPY_SEG)
    xed_encoder_request_set_seg0 (xe, xed_decoded_inst_get_seg_reg (xd, 0));
  if (flags & COPY_BASE)
    xed_encoder_request_set_base0 (xe, xed_decoded_inst_get_base_reg (xd, 0));
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
vex_encode_calc_fsbased_mem (struct encode_buf *b,
			     const xed_decoded_inst_t *xd, xed_reg_enum_t tmp)
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
  vex_copy_mem0 (&xe, xd, ~COPY_SEG);
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

static xed_reg_enum_t
vex_get_tmp_reg (struct encode_buf *b, unsigned short used)
{
  int ffs = __builtin_ffs (~used) - 1;
  eri_assert (ffs >= 0);
  xed_reg_enum_t tmp = XED_REG_RAX + ffs;
  eri_assert (eri_printf ("*** used: %lu, tmp: %s\n", used, xed_reg_enum_t2str (tmp)) == 0);
  vex_encode_save_gpr (b, tmp);
  return tmp;
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

  int fd = eri_open_path (v->path, "trans-", ERI_OPEN_WITHID, map[0][0]);
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

  int cfd = eri_open_path (v->path, "trans-bin-", ERI_OPEN_WITHID, map[0][0]);
  eri_assert (eri_fwrite (cfd, (const char *) b->p, b->off) == 0);
  eri_assert (eri_fclose (cfd) == 0);
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

static void *
vex_translate (struct vex *v, unsigned long rip)
{
  unsigned long map[v->max_inst_count][2];

  size_t inst_size = eri_round_up (XED_MAX_INSTRUCTION_BYTES, 16);
  size_t size = eri_min (32, v->max_inst_count) * inst_size;
  struct encode_buf b = {
    &v->epool, size, eri_assert_mtmalloc (&v->epool, size)
  };

  vex_encode_restore_gpr (&b, XED_REG_RSP);

  xed_state_t state;
  xed_state_init2 (&state, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

  char branch = 0;
  int i;
  for (i = 0; ! branch && i < v->max_inst_count; ++i)
    {
      eri_assert (eri_printf ("%lx\n", rip) == 0);

      map[i][0] = rip;
      map[i][1] = b.off;

      xed_decoded_inst_t xd;
      vex_decode (rip, v->pagesize, &xd);

      vex_dump_inst (rip, &xd);

      xed_uint_t length = xed_decoded_inst_get_length (&xd);
      const xed_inst_t *xi = xed_decoded_inst_inst (&xd);

      xed_iform_enum_t iform = xed_decoded_inst_get_iform_enum (&xd);
      xed_iclass_enum_t iclass = xed_iform_to_iclass (iform);

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
      char ref_fs = 0, has_relbr = 0;

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

	      vex_mark_used_reg (regs, base);
	      vex_mark_used_reg (regs, index);

	      if (seg == XED_REG_FS)
		{
		  eri_assert (op_name != XED_OPERAND_AGEN);
		  eri_assert (! xed_operand_values_has_real_rep (&xd));
		  ref_fs = 1;
		}
	    }
	  else if (op_name == XED_OPERAND_MEM1)
	    {
	      xed_reg_enum_t base = xed_decoded_inst_get_base_reg (&xd, 1);
	      xed_reg_enum_t seg = xed_decoded_inst_get_seg_reg (&xd, 1);
	      vex_assert_common_regs (base);
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
	  eri_assert (! ref_fs);

	  vex_encode_call (&b, VEX_CTX_SYSCALL);
	  branch = 1;
	}
      else if (vex_is_transfer (iclass))
	{
	  if ((iclass == XED_ICLASS_JMP || iclass == XED_ICLASS_CALL_NEAR)
	      && ! has_relbr)
	    {
	      if (iclass == XED_ICLASS_CALL_NEAR)
		{
		  vex_encode_inc_rip (&b, length);
		  vex_encode_push_rip (&b);
		}

	      xed_reg_enum_t tmp = vex_get_tmp_reg (&b, regs);
	      if (ref_fs)
		{
		  /* e.g. jmp	*%fs:(%rax) */
		  vex_encode_calc_fsbased_mem (&b, &xd, tmp);

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
		  xed_encoder_request_set_effective_operand_width (
		    &xe, xed_operand_values_get_effective_operand_width (&xd));

		  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, tmp);
		  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

		  xed_encoder_request_set_memory_operand_length (&xe, 8);
		  xed_encoder_request_set_mem0 (&xe);
		  vex_copy_mem0 (&xe, &xd, ~0);
		  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_MEM0);

		  vex_encode (&b, &xe);
		}

	      /* movq	%tmp, %fs:RIP */
	      vex_encode_save_rip (&b, tmp);
	      vex_encode_restore_gpr (&b, tmp);
	    }
	  else if (iclass == XED_ICLASS_RET_NEAR)
	    {
	      xed_reg_enum_t tmp = vex_get_tmp_reg (&b, regs);
	      /*
		 movq	(%rsp), %tmp
		 movq	%tmp, %fs:RIP
		 movq	%fs:TMP, %tmp
		 leaq	imm16(%rsp), %rsp
	      */
	      xed_encoder_request_t xe;
	      xed_encoder_request_zero_set_mode (&xe, &state);

	      xed_encoder_request_set_iclass (&xe, XED_ICLASS_MOV);
	      xed_encoder_request_set_effective_operand_width (&xe, 64);

	      xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, tmp);
	      xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

	      xed_encoder_request_set_memory_operand_length (&xe, 8);
	      xed_encoder_request_set_mem0 (&xe);
	      xed_encoder_request_set_base0 (&xe, XED_REG_RSP);
	      xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_MEM0);

	      vex_encode (&b, &xe);

	      vex_encode_save_rip (&b, tmp);
	      vex_encode_restore_gpr (&b, tmp);

	      xed_uint64_t uimm = xed_decoded_inst_get_unsigned_immediate (&xd);
	      if (uimm != 0)
		{
		  xed_encoder_request_zero_set_mode (&xe, &state);

		  xed_encoder_request_set_iclass (&xe, XED_ICLASS_LEA);
		  xed_encoder_request_set_effective_operand_width (&xe, 64);

		  xed_encoder_request_set_reg (&xe, XED_OPERAND_REG0, XED_REG_RSP);
		  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_REG0);

		  xed_encoder_request_set_agen (&xe);
		  xed_encoder_request_set_base0 (&xe, XED_REG_RSP);
		  xed_encoder_request_set_memory_displacement (&xe, uimm, 4);
		  xed_encoder_request_set_operand_order (&xe, 1, XED_OPERAND_AGEN);

		  vex_encode (&b, &xe);
		}
	    }
	  else
	    {
	      eri_assert (has_relbr);

	      vex_encode_inc_rip (&b, length);
	      xed_int32_t disp = xed_decoded_inst_get_branch_displacement (&xd);

	      if (iclass == XED_ICLASS_JMP)
		vex_encode_inc_rip (&b, disp);
	      else if (iclass == XED_ICLASS_CALL_NEAR)
		{
		  vex_encode_push_rip (&b);
		  vex_encode_inc_rip (&b, disp);
		}
	      else
		{
		  /*
			e.g. ja	1f
			jmp	2f
		     1: vex_encode_inc_rip (disp)
		     2:
		  */
		  struct encode_buf bjmp = {
		    &v->pool, inst_size, eri_assert_mtmalloc (&v->pool, inst_size)
		  };

		  struct encode_buf binc = {
		    &v->pool, 32 * inst_size,
		    eri_assert_mtmalloc (&v->pool, 32 * inst_size)
		  };

		  vex_encode_inc_rip (&binc, disp);

		  /* jmp	2f */
		  xed_encoder_request_t xe;
		  xed_encoder_request_zero_set_mode (&xe, &state);

		  xed_encoder_request_set_iclass (&xe, XED_ICLASS_JMP);
		  /* xed_encoder_request_set_effective_operand_width (&xe, 64); */

		  xed_encoder_request_set_relbr (&xe);
		  xed_encoder_request_set_branch_displacement (
		    &xe, binc.off, vex_get_disp_nbytes (binc.off, A_D | A_B));
		  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_RELBR);

		  vex_encode (&bjmp, &xe);

		  /* e.g. ja	1f */
		  xed_encoder_request_zero_set_mode (&xe, &state);

		  xed_encoder_request_set_iclass (&xe, iclass);

		  xed_encoder_request_set_relbr (&xe);
		  xed_encoder_request_set_branch_displacement (&xe, bjmp.off, 1);
		  xed_encoder_request_set_operand_order (&xe, 0, XED_OPERAND_RELBR);

		  vex_encode (&b, &xe);

		  vex_concat (&b, &bjmp);
		  vex_concat (&b, &binc);

		  eri_assert_mtfree (bjmp.pool, bjmp.p);
		  eri_assert_mtfree (binc.pool, binc.p);
		}
	    }
	  branch = 1;
	}
      else if (ref_fs)
	{
	  xed_reg_enum_t tmp = vex_get_tmp_reg (&b, regs);
	  vex_encode_calc_fsbased_mem (&b, &xd, tmp);

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

      if (! vex_is_transfer (iclass))
	vex_encode_inc_rip (&b, length);
      rip += length;
    }

  vex_encode_jmp (&b, VEX_CTX_BACK);

  save_translated (v, map, i, &b);
  return b.p;
}

static struct entry *
vex_get_entry (struct vex *v, unsigned long rip)
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
	__atomic_store_n (&e->insts, vex_translate (v, rip), __ATOMIC_RELEASE);
      eri_unlock (&e->trans_lock, 1);
    }
  return e;
}

asm ("  .text						\n\
  .align 16						\n\
  .type vex_execute, @function				\n\
vex_execute:						\n\
  .cfi_startproc					\n\
  .cfi_undefined %rip					\n\
  leaq	1f(%rip), %rax					\n\
  movq	%rax, %fs:" RET "				\n\
  movq	%rsp, %fs:" TOP "				\n\
  pushq	%fs:" RFLAGS "					\n\
  popfq							\n\
  movq	%fs:" RAX ", %rax				\n\
  movq	%fs:" RDI ", %rdi				\n\
  pushq	%fs:" INSTS "					\n\
  ret							\n\
1:							\n\
  ret							\n\
  .cfi_endproc						\n\
  .size vex_execute, .-vex_execute			\n\
  .previous						\n"
);

/* static */ void vex_execute (void);

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
  while (1)
    {
      struct entry *e = vex_get_entry (c->vex, c->ctx.comm.rip);
      c->ctx.insts = (unsigned long) e->insts;

      /* ERI_ASSERT_SYSCALL (exit, 0); */
      vex_execute ();

      __atomic_sub_fetch (&e->refs, 1, __ATOMIC_RELEASE);
    }
  eri_assert (0);
}

void
eri_vex_enter (char *buf, size_t size,
	       const struct eri_vex_context *ctx,
	       const char *path)
{
  size_t page = ctx->pagesize;
  struct vex v = { page, path };

  ERI_LST_INIT_LIST (context, &v);

  eri_assert ((unsigned long) buf % page == 0 && size % page == 0);
  size_t psize = size / page / 4 * page;
  eri_assert (eri_init_pool (&v.pool.pool, buf, psize) == 0);

  char *ebuf = buf + psize;
  size_t esize = size - psize;
  eri_assert (eri_init_pool (&v.epool.pool, ebuf, esize) == 0);

  ERI_ASSERT_SYSCALL (mprotect, ebuf, esize, 0x7);

  v.max_inst_count = 256;

  xed_register_abort_function (vex_xed_abort, 0);
  xed_tables_init ();

  struct context *c = eri_assert_mtcalloc (&v.pool, sizeof *c);

  c->ctx.syscall = (unsigned long) vex_syscall;
  c->ctx.back = (unsigned long) vex_back;

  c->stack = eri_assert_mtcalloc (&v.pool, 8 * 1024 * 1024);
  c->ctx.top = (unsigned long) c->stack + 8 * 1024 * 1024;

  eri_memcpy (&c->ctx.comm, &ctx->comm, sizeof c->ctx.comm);

  c->vex = &v;
  context_lst_append (&v, c);

  ERI_ASSERT_SYSCALL (arch_prctl, ERI_ARCH_SET_FS, c);
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
