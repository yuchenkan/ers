#ifndef ERI_TST_TST_LIVE_ENTRY_H
#define ERI_TST_TST_LIVE_ENTRY_H

#include "public/common.h"

#include "live-entry.h"

#define TST_LIVE_SYNC_JMP_REG		r8
#define TST_LIVE_SYNC_JMP_UREG		R8

#define TST_LIVE_VAL(sz, v) \
  ((v) * (1ul << (_ERS_ATOMIC_SIZE (sz) * 8)))

#define TST_LIVE_STOR_IMM_VAL(sz)	TST_LIVE_VAL (sz, 0xfe)

#define TST_LIVE_LOAD_REG_DST		ERI_RBX
#define TST_LIVE_LOAD_REG_MEM		rbx

#define TST_LIVE_CMP_REG		ERI_RSP
#define TST_LIVE_CMP_REG_MEM		rbp

#define TST_LIVE_STOR_REG_SRC		ERI_RCX
#define TST_LIVE_STOR_REG_MEM		rdx

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

struct tst_context
{
  uint64_t rax;
  uint64_t rbx;
  uint64_t rcx;
  uint64_t rdx;
  uint64_t rdi;
  uint64_t rsi;
  uint64_t rbp;
  uint64_t rsp;
  uint64_t r8;
  uint64_t r9;
  uint64_t r10;
  uint64_t r11;
  uint64_t r12;
  uint64_t r13;
  uint64_t r14;
  uint64_t r15;
  uint64_t rip;
  uint64_t rflags;
};

void tst_live_entry (struct tst_context *ctx);

#define TST_LIVE_ENTRY_ADDRS(entry) \
extern uint8_t _ERS_PASTE (tst_live_entry_raw_enter_, entry)[];		\
extern uint8_t _ERS_PASTE (tst_live_entry_raw_leave_, entry)[];		\
extern uint8_t _ERS_PASTE (tst_live_entry_enter_, entry)[];		\
extern uint8_t _ERS_PASTE (tst_live_entry_leave_, entry)[];

TST_LIVE_ENTRY_ADDRS (syscall)
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

TST_ATOMIC_SIZES32 (TST_LIVE_ENTRY_ATOMIC_ADDRS, stor_imm)
TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, stor_reg)

TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, inc)
TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, dec)

TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, xchg)

TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, cmpxchg_eq)
TST_ATOMIC_SIZES (TST_LIVE_ENTRY_ATOMIC_ADDRS, cmpxchg_ne)

#endif

#endif
