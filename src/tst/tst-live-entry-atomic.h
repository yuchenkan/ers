#ifndef TST_TST_LIVE_ENTRY_ATOMIC_H
#define TST_TST_LIVE_ENTRY_ATOMIC_H

#include <stdint.h>

#include <common.h>

#include <lib/util.h>
#include <tst/tst-live-entry.h>

#define TST_LIVE_ENTRY_ATOMIC_OP2(src, dst, sz) \
  ERI_PASTE (ERI_PASTE2 (load_, src, _), ERI_PASTE2 (dst, _, sz))

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

#endif
