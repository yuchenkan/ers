#include <public.h>
#include <common.h>

#include <lib/util.h>
#include <lib/registers.h>
#include <tst/tst-live-entry-atomic.h>
#include <tst/generated/registers.h>

#define OP(reg, mem, sz) \
  ERI_PASTE (ERI_PASTE2 (cmpxchg_, reg, _), ERI_PASTE2 (mem, _, sz))

#define ASM_SIZE(sz, creg, reg, mem) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (reg, mem, sz),				\
	ERI_EVAL (ERI_PASTE (cmpxchg, sz)				\
			%ERI_PASTE (ERI_, creg) (sz), (%mem)),		\
	ERS_ATOMIC_CMPXCHG (0, sz, %ERI_PASTE (ERI_, creg) (sz), (%mem)))

#define ASM(creg, reg, cmem, mem) \
TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (ASM_SIZE, creg, reg, mem)

TST_FOREACH_GENERAL_REG2 (ASM)

struct caze
{
  struct tst_live_entry_atomic_case caze;
  uint64_t mask;
  uint64_t rax, val; /* low bits according to size */
};

static eri_unused void info (struct caze *caze);

static void
info (struct caze *caze)
{
  eri_info ("%s %u %lx %lx\n",
	    caze->caze.name, !! caze->caze.init, caze->rax, caze->val);
}

static void
init (struct tst_live_entry_mcontext *tctx, uint64_t *val,
      struct caze *caze)
{
  uint64_t m = caze->mask;
  tctx->rax = (tctx->rax & ~m) | (caze->rax & m);
  *val = (*val & ~m) | (caze->val & m);
}

static struct caze cases[] = {

#define INFO	0 // info

#define MASK_b	0xff
#define MASK_w	0xffff
#define MASK_l	0xffffffff
#define MASK_q	0xffffffffffffffff

/* XXX: auto generate this */
#define _REG_IS_NOT_RAX_rax	0
#define _REG_IS_NOT_RAX_rbx	1
#define _REG_IS_NOT_RAX_rcx	1
#define _REG_IS_NOT_RAX_rdx	1
#define _REG_IS_NOT_RAX_rdi	1
#define _REG_IS_NOT_RAX_rsi	1
#define _REG_IS_NOT_RAX_rsp	1
#define _REG_IS_NOT_RAX_rbp	1
#define _REG_IS_NOT_RAX_r8	1
#define _REG_IS_NOT_RAX_r9	1
#define _REG_IS_NOT_RAX_r10	1
#define _REG_IS_NOT_RAX_r11	1
#define _REG_IS_NOT_RAX_r12	1
#define _REG_IS_NOT_RAX_r13	1
#define _REG_IS_NOT_RAX_r14	1
#define _REG_IS_NOT_RAX_r15	1

#define REG_IS_NOT_RAX(mem) ERI_PASTE (_REG_IS_NOT_RAX_, mem)

#define DO_CASE_SIZE(sz, reg, mem, val) \
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (reg, mem, sz),			\
				     mem, INFO, init),			\
    ERI_PASTE (MASK_, sz), 0x123456789abcdef0, val }

#define CASE_SIZE(sz, reg, mem) \
  ERI_PP_IF (REG_IS_NOT_RAX (mem),					\
	     DO_CASE_SIZE (sz, reg, mem, 0x123456789abcdef0),		\
	     DO_CASE_SIZE (sz, reg, mem, 0x123456789abcdef1),)		\
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (reg, mem, sz),			\
				     mem, INFO, 0) },			\
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (OP (reg, mem, sz),		\
					   mem, INFO) },

#define CASE(creg, reg, cmem, mem) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (CASE_SIZE, reg, mem)

  TST_FOREACH_GENERAL_REG2 (CASE)
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0)
