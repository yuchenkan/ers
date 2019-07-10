#ifndef TST_LIVE_TST_TST_ENTRY_ATOMIC_H
#define TST_LIVE_TST_TST_ENTRY_ATOMIC_H

#include <stdint.h>

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/cpu.h>
#include <common/debug.h>

#include <tst/tst-syscall.h>
#include <live/tst/tst-entry.h>

#define TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER(op)	ERI_PASTE2 (ctrl_, op, _enter)
#define TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER(op)	ERI_PASTE2 (expr_, op, _enter)
#define TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE(op)	ERI_PASTE2 (expr_, op, _leave)

#define TST_LIVE_ENTRY_ATOMIC_TEXT(op, ctrl, expr) \
extern uint8_t TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (op)[];			\
asm (ERI_STR (TST_LIVE_ENTRY_ATOMIC_CTRL_ENTER (op)) ": "		\
     ERI_STR (ctrl));							\
									\
extern uint8_t TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (op)[];			\
extern uint8_t TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (op)[];			\
asm (ERI_STR (TST_LIVE_ENTRY_ATOMIC_EXPR_ENTER (op)) ": "		\
     ERI_STR (expr) "; "						\
     ERI_STR (TST_LIVE_ENTRY_ATOMIC_EXPR_LEAVE (op)) ":");

#define TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT_NAME(op, reg, mem, sz) \
  ERI_PASTE2 (ERI_PASTE2 (op, _, reg), _, ERI_PASTE2 (mem, _, sz))

#define _TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT_SIZE(sz, cop, op, \
						 creg, reg, mem) \
TST_LIVE_ENTRY_ATOMIC_TEXT (						\
	TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT_NAME (op, reg, mem, sz),	\
	ERI_EVAL (ERI_PASTE (op, sz)					\
			%ERI_PASTE (ERI_, creg) (sz), (%mem)),		\
	ERI_PASTE (ERS_ATOMIC_, cop) (0, sz,				\
				%ERI_PASTE (ERI_, creg) (sz), (%mem)))

#define _TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT(creg, reg, cmem, mem, cop, op) \
ERI_FOREACH_REG_SIZE (_TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT_SIZE,		\
		      cop, op, creg, reg, mem)

#define TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT(cop, op) \
TST_FOREACH_GENERAL_REG2 (_TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT, cop, op)

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

#define _TST_LIVE_ENTRY_ATOMIC_COMMON2_CASE_SIZE(sz, op, reg, mem, info) \
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT (					\
	TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT_NAME (op, reg, mem, sz),	\
	mem, info, 0),	\
  TST_LIVE_ENTRY_ATOMIC_CASE_INIT_FAULT (				\
	TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT_NAME (op, reg, mem, sz),	\
	mem, info),

#define _TST_LIVE_ENTRY_ATOMIC_COMMON2_CASE(creg, reg, cmem, mem, op, info) \
  ERI_FOREACH_REG_SIZE (_TST_LIVE_ENTRY_ATOMIC_COMMON2_CASE_SIZE,	\
			op, reg, mem, info)

#define TST_LIVE_ENTRY_ATOMIC_COMMON2_CASES(cop, op, info, seed, debug) \
TST_LIVE_ENTRY_ATOMIC_COMMON2_TEXT (cop, op)				\
									\
static struct tst_live_entry_atomic_case _cases[] = {			\
  TST_FOREACH_GENERAL_REG2 (_TST_LIVE_ENTRY_ATOMIC_COMMON2_CASE,	\
			    op, info)					\
};									\
									\
TST_LIVE_ENTRY_ATOMIC_DEFINE_START (_cases, seed, debug)

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
