/* vim: set ft=gas: */

#include "public/impl.h"

#include "lib/util.h"
#include "lib/syscall.h"
#include "tst/tst-live-entry-basic.h"
#include "tst/tst-live-entry-common-offsets.h"

  .text

#define TST_LIVE_ENTRY(entry, raw, tst, ...) \
  .align 16;								\
ERI_GLOBAL_HIDDEN (_ERS_PASTE (tst_live_entry_raw_enter_, entry))	\
  raw (__VA_ARGS__);							\
ERI_GLOBAL_HIDDEN (_ERS_PASTE (tst_live_entry_raw_leave_, entry))	\
  ret;									\
ERI_GLOBAL_HIDDEN (_ERS_PASTE (tst_live_entry_enter_, entry))		\
  tst (__VA_ARGS__);							\
ERI_GLOBAL_HIDDEN (_ERS_PASTE (tst_live_entry_leave_, entry))		\
  ret;

#define RAW_DO_SYSCALL()	syscall
#define DO_SYSCALL()		_ERS_SYSCALL

TST_LIVE_ENTRY (do_syscall, RAW_DO_SYSCALL, DO_SYSCALL)

#define RAW_HOLD_SYSCALL()	nop
#define HOLD_SYSCALL()		_ERS_SYSCALL

TST_LIVE_ENTRY (hold_syscall, RAW_HOLD_SYSCALL, HOLD_SYSCALL)

#define SYNC_JMP_REG		TST_LIVE_SYNC_JMP_REG

#define TST_SYNC_JMP(raw) \
  ERI_PP_IIF (raw,							\
	      jmp	*(%SYNC_JMP_REG),				\
	      _ERS_SYNC_ASYNC (jmp	*(%SYNC_JMP_REG)));		\
  nop;									\

#define RAW_SYNC_JMP()		TST_SYNC_JMP (1)
#define SYNC_JMP()		TST_SYNC_JMP (0)

TST_LIVE_ENTRY (sync_jmp, RAW_SYNC_JMP, SYNC_JMP)

#define RAW_SYNC_REP() \
  ERI_GLOBAL_HIDDEN (tst_live_raw_sync_rep);				\
tst_live_raw_sync_rep:							\
  rep movsq;
#define SYNC_REP() \
  _ERS_SYNC_ASYNC (ERI_GLOBAL_HIDDEN (tst_live_sync_rep);		\
tst_live_sync_rep:							\
  rep movsq);

TST_LIVE_ENTRY (sync_rep, RAW_SYNC_REP, SYNC_REP)

#define LOAD_REG_DST		TST_LIVE_LOAD_REG_DST
#define LOAD_REG_MEM		TST_LIVE_LOAD_REG_MEM

#define RAW_LOAD(sz) \
  _ERS_PASTE (mov, sz)	(%LOAD_REG_MEM), %LOAD_REG_DST (sz)
#define LOAD(sz) \
  _ERS_ATOMIC_LOAD (sz, (%LOAD_REG_MEM), %LOAD_REG_DST (sz))

#define TST_LOAD(sz) \
  TST_LIVE_ENTRY (_ERS_PASTE (load, sz), RAW_LOAD, LOAD, sz)

TST_ATOMIC_SIZES (TST_LOAD)

#define CMP_REG			TST_LIVE_CMP_REG
#define CMP_REG_MEM		TST_LIVE_CMP_REG_MEM

#define RAW_CMP(sz) \
  _ERS_PASTE (cmp, sz)	%CMP_REG (sz), (%CMP_REG_MEM)

#define TST_LOAD_CMP(sz, res, reg) \
  _ERS_PASTE (cmp, sz)	reg, res

#define TST_ATOMIC_CMP(sz, reg, mem) \
  _ERS_ATOMIC_COMMON_LOAD (sz, mem, TST_LOAD_CMP, reg)

#define CMP(sz) \
  TST_ATOMIC_CMP (sz, %CMP_REG (sz), (%CMP_REG_MEM))

#define TST_CMP(sz, name) \
  TST_LIVE_ENTRY (_ERS_PASTE (name, sz), RAW_CMP, CMP, sz)

TST_ATOMIC_SIZES (TST_CMP, cmp_eq)
TST_ATOMIC_SIZES (TST_CMP, cmp_ne)

#define STORE_IMM_VAL		TST_LIVE_STORE_IMM_VAL
#define STORE_REG_SRC		TST_LIVE_STORE_REG_SRC
#define STORE_REG_MEM		TST_LIVE_STORE_REG_MEM

#define RAW_STORE_IMM(sz) \
  _ERS_PASTE (mov, sz)	$STORE_IMM_VAL (sz), (%STORE_REG_MEM)
#define STORE_IMM(sz) \
  _ERS_ATOMIC_STORE (sz, $STORE_IMM_VAL (sz), (%STORE_REG_MEM))

#define TST_STORE_IMM(sz) \
  TST_LIVE_ENTRY (_ERS_PASTE (store_imm, sz), RAW_STORE_IMM, STORE_IMM, sz)

#define RAW_STORE_REG(sz) \
  _ERS_PASTE (mov, sz)	%STORE_REG_SRC (sz), (%STORE_REG_MEM)
#define STORE_REG(sz) \
  _ERS_ATOMIC_STORE (sz, %STORE_REG_SRC (sz), (%STORE_REG_MEM))

#define TST_STORE_REG(sz) \
  TST_LIVE_ENTRY (_ERS_PASTE (store_reg, sz), RAW_STORE_REG, STORE_REG, sz)

TST_ATOMIC_SIZES32 (TST_STORE_IMM)
TST_ATOMIC_SIZES (TST_STORE_REG)

#define INC_REG_MEM		TST_LIVE_INC_REG_MEM
#define DEC_REG_MEM		TST_LIVE_DEC_REG_MEM

#define RAW_INC_DEC(sz, uinc, inc) \
  _ERS_PASTE (inc, sz)	(%_ERS_PASTE (uinc, _REG_MEM))
#define INC_DEC(sz, uinc, inc) \
  _ERS_PASTE (_ERS_ATOMIC_, uinc) (sz, (%_ERS_PASTE (uinc, _REG_MEM)))

#define TST_INC_DEC(sz, uinc, inc) \
  TST_LIVE_ENTRY (_ERS_PASTE (inc, sz), RAW_INC_DEC, INC_DEC, sz, uinc, inc)

TST_ATOMIC_SIZES (TST_INC_DEC, INC, inc)
TST_ATOMIC_SIZES (TST_INC_DEC, DEC, dec)

#define XCHG_REG		TST_LIVE_XCHG_REG
#define XCHG_REG_MEM		TST_LIVE_XCHG_REG_MEM

#define RAW_XCHG(sz) \
  _ERS_PASTE (xchg, sz)	%XCHG_REG (sz), (%XCHG_REG_MEM)
#define XCHG(sz) \
  _ERS_ATOMIC_XCHG (sz, %XCHG_REG (sz), (%XCHG_REG_MEM))

#define TST_XCHG(sz) \
  TST_LIVE_ENTRY (_ERS_PASTE (xchg, sz), RAW_XCHG, XCHG, sz)

TST_ATOMIC_SIZES (TST_XCHG)

#define CMPXCHG_REG		TST_LIVE_CMPXCHG_REG

#define RAW_CMPXCHG(sz) \
  _ERS_PASTE (cmpxchg, sz)	%CMPXCHG_REG (sz), (%CMPXCHG_REG (q))
#define CMPXCHG(sz) \
  _ERS_ATOMIC_CMPXCHG (sz, %CMPXCHG_REG (sz), (%CMPXCHG_REG (q)))

#define TST_CMPXCHG(sz, name) \
  TST_LIVE_ENTRY (_ERS_PASTE (name, sz), RAW_CMPXCHG, CMPXCHG, sz)

TST_ATOMIC_SIZES (TST_CMPXCHG, cmpxchg_eq)
TST_ATOMIC_SIZES (TST_CMPXCHG, cmpxchg_ne)

ERI_GLOBAL_HIDDEN_FUNCTION (tst_do_syscall)
  pushq	%rbx
  xorq	%rbx, %rbx
  pushq	24(%rsp)
  pushq	24(%rsp)
  call	eri_live_entry_do_syscall
  addq	$16, %rsp
  popq	%rbx
  ret
  .size tst_do_syscall, . - tst_do_syscall
