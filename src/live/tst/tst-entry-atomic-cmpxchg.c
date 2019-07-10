#include <public/public.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <common/debug.h>

#include <live/tst/tst-registers.h>
#include <live/tst/tst-entry-atomic.h>

TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT (CMPXCHG, cmpxchg)

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

#define NAME(reg, mem, sz) \
  TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT_NAME (cmpxchg, reg, mem, sz)

#define DO_CASE_SIZE(sz, reg, mem, val) \
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (NAME (reg, mem, sz),		\
				     mem, INFO, init),			\
    ERI_PASTE (MASK_, sz), 0x123456789abcdef0, val }

#define CASE_SIZE(sz, reg, mem) \
  ERI_PP_IF (REG_IS_NOT_RAX (mem),					\
	     DO_CASE_SIZE (sz, reg, mem, 0x123456789abcdef0),		\
	     DO_CASE_SIZE (sz, reg, mem, 0x123456789abcdef1),)		\
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (NAME (reg, mem, sz),		\
				     mem, INFO, 0) },			\
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (NAME (reg, mem, sz),		\
					   mem, INFO) },

#define CASE(creg, reg, cmem, mem) \
  ERI_FOREACH_REG_SIZE (CASE_SIZE, reg, mem)

  TST_FOREACH_GENERAL_REG2 (CASE)
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0, 0)
