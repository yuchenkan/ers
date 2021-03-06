#include <public/public.h>

#include <lib/util.h>
#include <lib/cpu.h>
#include <common/debug.h>

#include <live/tst/tst-registers.h>
#include <live/tst/tst-entry-atomic.h>

#define NAME(inc, mem, sz) \
  ERI_PASTE (ERI_PASTE2 (inc, _, mem), ERI_PASTE (_, sz))

#define TEXT_SIZE(sz, cinc, inc, mem) \
TST_LIVE_ENTRY_ATOMIC_TEXT (NAME (inc, mem, sz),			\
	ERI_EVAL (ERI_PASTE (inc, sz)	(%mem)),			\
	ERI_PASTE (ERS_ATOMIC_, cinc) (0, sz, (%mem)))

#define TEXT(cmem, mem, cinc, inc) \
ERI_FOREACH_REG_SIZE (TEXT_SIZE, cinc, inc, mem)

TST_FOREACH_GENERAL_REG (TEXT, INC, inc)
TST_FOREACH_GENERAL_REG (TEXT, DEC, dec)

struct caze
{
  struct tst_live_entry_atomic_case caze;
  uint64_t val;
};

static eri_unused void info (struct caze *caze);

static void
info (struct caze *caze)
{
  eri_info ("%s %lx %lx\n", caze->caze.name, caze->caze.init, caze->val);
}

static void
init (struct tst_live_entry_mcontext *tctx, uint64_t *val,
      struct caze *caze)
{
  *val = caze->val;
}

static struct caze cases[] = {

#define INFO	0 // info

#define DO_CASE_SIZE(sz, mem, inc, val) \
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (NAME (inc, mem, sz),		\
				     mem, INFO, init), val }

#define DO_CASE_RAND_SIZE(sz, mem, inc) \
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT (NAME (inc, mem, sz), mem, INFO, 0) }

#define CASE_SIZE(sz, mem) \
  DO_CASE_SIZE (sz, mem, inc, -1), DO_CASE_SIZE (sz, mem, inc, 0),	\
  DO_CASE_SIZE (sz, mem, inc, 1), DO_CASE_SIZE (sz, mem, dec, -1),	\
  DO_CASE_SIZE (sz, mem, dec, 0), DO_CASE_SIZE (sz, mem, dec, 1),	\
  DO_CASE_RAND_SIZE (sz, mem, inc), DO_CASE_RAND_SIZE (sz, mem, dec),	\
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (NAME (inc, mem, sz),		\
					   mem, INFO) },		\
  { TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (NAME (dec, mem, sz),		\
					   mem, INFO) },

#define CASE(cmem, mem) \
  ERI_FOREACH_REG_SIZE (CASE_SIZE, mem)

  TST_FOREACH_GENERAL_REG (CASE)
};

TST_LIVE_ENTRY_ATOMIC_DEFINE_START (cases, 0, 0)
