#ifndef ERI_TST_TST_LIVE_ENTRY_H
#define ERI_TST_TST_LIVE_ENTRY_H

#include "public/common.h"

#include "live-entry.h"

#define TST_LIVE_SYNC_JMP_REG		r8
#define TST_LIVE_SYNC_JMP_UREG		R8

#define TST_LIVE_VAL(sz, v) \
  ((v) * (1ul << (_ERS_ATOMIC_SIZE (sz) * 8)))

#define TST_LIVE_STORE_IMM_VAL(sz)	TST_LIVE_VAL (sz, 0xfe)

#define TST_LIVE_LOAD_REG_DST		ERI_RBX
#define TST_LIVE_LOAD_REG_MEM		rbx

#define TST_LIVE_CMP_REG		ERI_RSP
#define TST_LIVE_CMP_REG_MEM		rbp

#define TST_LIVE_STORE_REG_SRC		ERI_RCX
#define TST_LIVE_STORE_REG_MEM		rdx

#define TST_LIVE_INC_REG_MEM		rdi
#define TST_LIVE_DEC_REG_MEM		rsi

#define TST_LIVE_XCHG_REG		ERI_R9
#define TST_LIVE_XCHG_REG_MEM		r10

#define TST_LIVE_CMPXCHG_REG		ERI_R11

#define TST_ATOMIC_SIZES32(op, ...) \
  op (b, ##__VA_ARGS__) op (w, ##__VA_ARGS__)				\
  op (l, ##__VA_ARGS__)

#define TST_ATOMIC_SIZES(op, ...) \
  TST_ATOMIC_SIZES32 (op, ##__VA_ARGS__) op (q, ##__VA_ARGS__)

#ifndef __ASSEMBLER__

#include <stdint.h>

#define TST_LIVE_ENTRY_ADDRS(entry) \
extern uint8_t _ERS_PASTE (tst_live_entry_raw_enter_, entry)[];		\
extern uint8_t _ERS_PASTE (tst_live_entry_raw_leave_, entry)[];		\
extern uint8_t _ERS_PASTE (tst_live_entry_enter_, entry)[];		\
extern uint8_t _ERS_PASTE (tst_live_entry_leave_, entry)[];

TST_LIVE_ENTRY_ADDRS (do_syscall)
TST_LIVE_ENTRY_ADDRS (hold_syscall)

TST_LIVE_ENTRY_ADDRS (sync_jmp)

TST_LIVE_ENTRY_ADDRS (sync_rep)
extern uint8_t tst_live_raw_sync_rep[];
extern uint8_t tst_live_sync_rep[];

#define TST_LIVE_ENTRY_ATOMIC_ADDRS(sz, entry) \
extern uint8_t _ERS_PASTE2 (tst_live_entry_raw_enter_, entry, sz)[];	\
extern uint8_t _ERS_PASTE2 (tst_live_entry_raw_leave_, entry, sz)[];	\
extern uint8_t _ERS_PASTE2 (tst_live_entry_enter_, entry, sz)[];	\
extern uint8_t _ERS_PASTE2 (tst_live_entry_leave_, entry, sz)[];

TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, load)

TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, cmp_eq)
TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, cmp_ne)

TST_ATOMIC_SIZES32 (TST_LIVE_ENTRY_ATOMIC_ADDRS, store_imm)
TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, store_reg)

TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, inc)
TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, dec)

TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, xchg)

TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, cmpxchg_eq)
TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, cmpxchg_ne)

#endif

#endif
