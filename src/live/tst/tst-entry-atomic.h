#ifndef TST_LIVE_TST_ENTRY_ATOMIC_H
#define TST_LIVE_TST_ENTRY_ATOMIC_H

#include <stdint.h>

#include <compiler.h>
#include <common.h>

#include <lib/util.h>
#include <tst/tst-syscall.h>
#include <live/tst/tst-entry.h>

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

#define TST_LIVE_ENTRY_ATOMIC_CASE_INIT(op, mem, info, init) \
  { ERI_STR (op),							\
    TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (op),				\
    TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (op),				\
    TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (op),				\
    __builtin_offsetof (struct tst_live_entry_mcontext, mem),		\
    info, init }

#define TST_LIVE_ENTRY_ATOMIC_FAULT	((void *) 1)

#define TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT(op, mem, info) \
  { ERI_STR (ERI_PASTE (op, _fault)),					\
    TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (op),				\
    TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (op),				\
    TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (op),				\
    __builtin_offsetof (struct tst_live_entry_mcontext, mem),		\
    info, TST_LIVE_ENTRY_ATOMIC_FAULT }

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


#define TST_LIVE_ENTRY_ATOMIC_DEFINE_START(cases, seed, debug) \
static struct tst_live_entry_atomic_anchor anchor;			\
									\
eri_noreturn void tst_live_start (void);				\
eri_noreturn void							\
tst_live_start (void)							\
{									\
  struct tst_rand rand;							\
  tst_rand_init (&rand, seed);						\
									\
  eri_global_enable_debug = debug;					\
  tst_live_entry_atomic_cases (&rand, cases, &anchor);			\
  tst_assert_sys_exit (0);						\
}

#endif
