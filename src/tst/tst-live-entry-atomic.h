#ifndef TST_TST_LIVE_ENTRY_ATOMIC_H
#define TST_TST_LIVE_ENTRY_ATOMIC_H

#include <stdint.h>

#include <compiler.h>
#include <common.h>

#include <lib/util.h>
#include <tst/tst-syscall.h>
#include <tst/tst-live-entry.h>

#define TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER(op)	ERI_PASTE2 (ctrl_, op, _enter)
#define TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER(op)	ERI_PASTE2 (expr_, op, _enter)
#define TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE(op)	ERI_PASTE2 (expr_, op, _leave)

#define TST_LIVE_ENTRY_ATOMIC_ASM(op, ctrl, expr) \
extern uint8_t TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (op)[];			\
asm (ERI_STR (TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (op)) ": "		\
     ERI_STR (ctrl));							\
									\
extern uint8_t TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (op)[];			\
extern uint8_t TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (op)[];			\
asm (ERI_STR (TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (op)) ": "		\
     ERI_STR (expr) "; "						\
     ERI_STR (TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (op)) ":");

#define TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE3(p, ...) \
  p (b, ##__VA_ARGS__)							\
  p (w, ##__VA_ARGS__)							\
  p (l, ##__VA_ARGS__)

#define TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE(p, ...) \
  TST_LIVE_ENTRY_ATOMIC_FOREACH_SIZE3 (p, ##__VA_ARGS__)		\
  p (q, ##__VA_ARGS__)

#define TST_LIVE_ENTRY_ATOMIC_CASE_INIT(op, mem, info, init) \
  { ERI_STR (op),							\
    TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (op),				\
    TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (op),				\
    TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (op),				\
    __builtin_offsetof (struct tst_live_entry_mcontext, mem),		\
    info, init }

struct tst_live_entry_atomic_case
{
  const char *name;
  void *ctrl_enter, *expr_enter, *expr_leave;
  uint16_t mem_off;

  void *info; /* void (*) (struct tst_live_entry_atomic_case *) */
  /*
   * void (*init) (struct tst_live_entry_mcontext *, uint64_t *,
   *		   struct tst_live_entry_atomic_case *)
   */
  void *init;
};

struct tst_live_entry_atomic_anchor
{
  struct tst_live_entry_mcontext *tctx;
  uint64_t *val;
  struct tst_live_entry_mcontext *ctrl_tctx;
  uint64_t *ctrl_val;
  struct tst_live_entry_mcontext *expr_tctx;
};

void tst_live_entry_atomic (struct tst_rand *rand,
			    void *cases, uint32_t case_size, uint32_t count,
			    struct tst_live_entry_atomic_anchor *anchor);
#define tst_live_entry_atomic_cases(rand, cases, anchor) \
  tst_live_entry_atomic (rand, cases, sizeof (cases)[0],		\
			 eri_length_of (cases), anchor)

void tst_live_entry_atomic_common_info (
			struct tst_live_entry_atomic_case *caze);


#define TST_LIVE_ENTRY_ATOMIC_DEFINE_START(cases, debug) \
static struct tst_live_entry_atomic_anchor anchor;			\
									\
noreturn void tst_live_start (void);					\
noreturn void								\
tst_live_start (void)							\
{									\
  struct tst_rand rand;							\
  tst_rand_init (&rand);						\
									\
  eri_global_enable_debug = debug;					\
  tst_live_entry_atomic_cases (&rand, cases, &anchor);			\
  tst_assert_sys_exit (0);						\
}

#endif
