#include <compiler.h>
#include <common.h>

#include <public/impl.h>
#include <lib/util.h>
#include <lib/registers.h>
#include <tst/tst-syscall.h>
#include <tst/tst-live-entry-atomic.h>
#include <tst/generated/registers.h>

#define OP(reg, mem, sz) \
  ERI_PASTE (ERI_PASTE2 (cmpxchg_, reg, _), ERI_PASTE2 (mem, _, sz))

#define ASM_SIZE(sz, creg, reg, mem) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (reg, mem, sz),				\
	ERI_EVAL (ERI_PASTE (cmpxchg, sz)				\
			%ERI_PASTE (ERI_, creg) (sz), (%mem)),		\
	_ERS_ATOMIC_CMPXCHG (0, sz, %ERI_PASTE (ERI_, creg) (sz), (%mem)))

#define ASM(creg, reg, cmem, mem) \
TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (ASM_SIZE, creg, reg, mem)

TST_FOREACH_GENERAL_REG2 (ASM)

struct init_args
{
  uint64_t mask;
  uint64_t rax, val; /* low bits according to size */
};

struct caze
{
  struct tst_live_entry_atomic_case caze;
  struct init_args args;
};

static unused void info (struct caze *caze);

static void
info (struct caze *caze)
{
  eri_info ("%s %u %lx %lx\n",
	    caze->caze.name, !! caze->caze.init, caze->args.rax, caze->args.val);
}

static void
init (struct tst_live_entry_mcontext *tctx, uint64_t *val, void *args)
{
  struct init_args *a = args;
  uint64_t m = a->mask;
  tctx->rax = (tctx->rax & ~m) | (a->rax & m);
  *val = (*val & ~m) | (a->val & m);
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

#define DO_CASE_SIZE(sz, reg, mem, rax, val) \
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (reg, mem, sz),			\
				     mem, INFO, init),			\
    { ERI_PASTE (MASK_, sz), rax, val } },

#define CASE_SIZE(sz, reg, mem, rax, val) \
  ERI_PP_IF (REG_IS_NOT_RAX (mem), DO_CASE_SIZE (sz, reg, mem, rax, val))

#define CASE_RAND_SIZE(sz, reg, mem) \
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (reg, mem, sz), mem, INFO, 0) },

#define CASE(creg, reg, cmem, mem, rax, val) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (CASE_SIZE, reg, mem, rax, val)

#define CASE_RAND(creg, reg, cmem, mem) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (CASE_RAND_SIZE, reg, mem)

  TST_FOREACH_GENERAL_REG2 (CASE, 0x123456789abcdef0, 0x123456789abcdef0)
  TST_FOREACH_GENERAL_REG2 (CASE, 0x123456789abcdef0, 0x123456789abcdef1)

  TST_FOREACH_GENERAL_REG2 (CASE_RAND)
};

noreturn void tst_live_start (void);

noreturn void
tst_live_start (void)
{
  struct tst_rand rand;
  tst_rand_init (&rand);

  // eri_global_enable_debug = 1;
  static struct tst_live_entry_atomic_anchor anchor;
  tst_live_entry_atomic_cases (&rand, cases, &anchor);
  tst_assert_sys_exit (0);
}
