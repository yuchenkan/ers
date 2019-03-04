#ifndef ERS_PUBLIC_H
#define ERS_PUBLIC_H

#include <public/impl.h>

#define ERS_INIT			_ERS_INIT

#define ERS_SYSCALL(esc)		_ERS_SYSCALL (esc)

#define ERS_SYNC_ASYNC(esc, inst)	_ERS_SYNC_ASYNC (esc, inst)

#define ERS_ATOMIC_COMMON_LOAD(esc, size, mem, op, ...) \
  _ERS_ATOMIC_COMMON_LOAD (esc, size, mem, op, ##__VA_ARGS__)

#define ERS_ATOMIC_LOAD(esc, size, mem, reg) \
  _ERS_ATOMIC_LOAD (esc, size, mem, reg)

#define ERS_ATOMIC_STORE(esc, size, imm_or_reg, mem) \
  _ERS_ATOMIC_STORE (esc, size, imm_or_reg, mem)

#define ERS_ATOMIC_INC(esc, size, mem) \
  _ERS_ATOMIC_INC (esc, size, mem)

#define ERS_ATOMIC_DEC(esc, size, mem) \
  _ERS_ATOMIC_DEC (esc, size, mem)

#define ERS_ATOMIC_XCHG(esc, size, reg, mem) \
  _ERS_ATOMIC_XCHG (esc, size, reg, mem)

#define ERS_ATOMIC_CMPXCHG(esc, size, reg, mem) \
  _ERS_ATOMIC_CMPXCHG (esc, size, reg, mem)

#endif
