#include "tst/tst-live-entry-atomic.h"

struct pack
{
  void *expr_leave;
  struct tst_live_entry_atomic_anchor *anchor;

  uint64_t val;

  struct tst_live_entry_mcontext ctrl_tctx;
  uint64_t ctrl_val;
};

static uint8_t
ctrl_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  struct pack *pack = args;
  pack->ctrl_tctx = *tctx;
  pack->ctrl_val = pack->val;
  return 0;
}

static uint8_t
expr_step (struct tst_live_entry_mcontext *tctx, void *args)
{
  struct pack *pack = args;
  if (pack->anchor) pack->anchor->expr_tctx = tctx;
  eri_assert (tctx->rip == (uint64_t) pack->expr_leave);
  tst_assert_live_entry_mcontext_eq (&pack->ctrl_tctx, tctx,
				     ~TST_LIVE_ENTRY_MCONTEXT_RIP_MASK);
  eri_assert (pack->val == pack->ctrl_val);
  return 0;
}

static void
tst (struct tst_rand *rand, struct tst_live_entry_atomic_case *caze,
     struct tst_live_entry_atomic_anchor *anchor)
{
  if (caze->info) ((void (*) (void *)) caze->info) (caze);

  struct pack pack = { caze->expr_leave, anchor };
  struct tst_live_entry_mcontext tctx;
  uint64_t val;

  if (anchor)
    {
      anchor->tctx = &tctx;
      anchor->val = &val;
      anchor->ctrl_tctx = &pack.ctrl_tctx;
      anchor->ctrl_val = &pack.ctrl_val;
    }

  tst_live_entry_rand_fill_mcontext (rand, &tctx);
  *(uint64_t **)((uint8_t *) &tctx + caze->mem_off) = &pack.val;
  val = tst_rand_next (rand);
  if (caze->init)
    ((void (*) (struct tst_live_entry_mcontext *,
		uint64_t *, void *)) caze->init) (&tctx, &val, caze);

  pack.val = val;
  tctx.rip = (uint64_t) caze->ctrl_enter;
  tst_live_entry (&tctx, ctrl_step, &pack);

  pack.val = val;
  tctx.rip = (uint64_t) caze->expr_enter;
  tst_live_entry (&tctx, expr_step, &pack);
}

void
tst_live_entry_atomic (struct tst_rand *rand,
		       void *cases, uint32_t case_size, uint32_t count,
		       struct tst_live_entry_atomic_anchor *anchor)
{
  uint32_t i;
  for (i = 0; i < count; ++i)
    tst (rand, (void *) ((uint8_t *) cases + i * case_size), anchor);
  eri_debug ("done\n");
}

void
tst_live_entry_atomic_common_info (struct tst_live_entry_atomic_case *caze)
{
  eri_info ("%s %u\n", caze->name, !! caze->init);
}
