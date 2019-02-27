#include <compiler.h>
#include <common.h>

#include <public/impl.h>
#include <lib/util.h>
#include <lib/registers.h>
#include <tst/tst-syscall.h>
#include <tst/tst-live-entry-atomic.h>
#include <tst/generated/registers.h>

#define OP(inc, reg, sz) \
  ERI_PASTE (ERI_PASTE2 (inc, _, reg), ERI_PASTE (_, sz))

#define ASM_SIZE(sz, cinc, inc, reg) \
TST_LIVE_ENTRY_ATOMIC_ASM (OP (inc, reg, sz),				\
	ERI_EVAL (ERI_PASTE (inc, sz)	(%reg)),			\
	ERI_PASTE (_ERS_ATOMIC_, cinc) (0, sz, (%reg)))

#define ASM(creg, reg, cinc, inc) \
TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (ASM_SIZE, cinc, inc, reg)

TST_FOREACH_GENERAL_REG (ASM, INC, inc)
TST_FOREACH_GENERAL_REG (ASM, DEC, dec)

struct caze
{
  struct tst_live_entry_atomic_case caze;
  uint64_t val;
};

static unused void info (struct caze *caze);

static void
info (struct caze *caze)
{
  eri_info ("%s %u %lx\n", caze->caze.name, !! caze->caze.init, caze->val);
}

static void
init (struct tst_live_entry_mcontext *tctx, uint64_t *val, void *args)
{
  *val = *(uint64_t *) args;
}

static struct caze cases[] = {

#define INFO	0 // info

#define CASE_SIZE(sz, inc, val, reg) \
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (inc, reg, sz),			\
				    reg, INFO, init), val },

#define CASE_RAND_SIZE(sz, inc, reg) \
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (OP (inc, reg, sz), reg, INFO, 0) },

#define CASE(creg, reg, inc, val) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (CASE_SIZE, inc, val, reg)

#define CASE_RAND(creg, reg, inc) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE (CASE_RAND_SIZE, inc, reg)

  TST_FOREACH_GENERAL_REG (CASE, inc, -1)
  TST_FOREACH_GENERAL_REG (CASE, inc, 0)
  TST_FOREACH_GENERAL_REG (CASE, inc, 1)
  TST_FOREACH_GENERAL_REG (CASE, dec, -1)
  TST_FOREACH_GENERAL_REG (CASE, dec, 0)
  TST_FOREACH_GENERAL_REG (CASE, dec, 1)

  TST_FOREACH_GENERAL_REG (CASE_RAND, inc)
  TST_FOREACH_GENERAL_REG (CASE_RAND, dec)
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
