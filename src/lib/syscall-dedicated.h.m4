#ifndef ERI_LIB_SYSCALL_DEDICATED_H
#define ERI_LIB_SYSCALL_DEDICATED_H

#include "lib/syscall-common.h"

#ifndef __ASSEMBLER__
#include <stdint.h>

#define _eri_syscall_nr(nr, nargs, ...) \
  ({									\
    uint64_t __res;							\
    ERI_PASTE (_ERI_LOAD_ARGS_, nargs) (__VA_ARGS__)			\
    asm volatile (							\
      "syscall"								\
      : "=a" (__res)							\
      : "0" (nr) ERI_PASTE (_ERI_SYSCALL_ARGS_, nargs)			\
      : "memory", "cc", "r11", "cx"					\
    );									\
    __res;								\
  })

#define eri_syscall(name, ...) \
  _eri_syscall_nr (__NR_##name, eri_syscall_nargs (0, ##__VA_ARGS__),	\
		   ##__VA_ARGS__)

#define eri_syscall_nr(nr, ...) \
  _eri_syscall_nr (nr, eri_syscall_nargs (0, ##__VA_ARGS__), ##__VA_ARGS__)

#define eri_assert_syscall(...) \
  ({									\
    uint64_t _res = eri_syscall (__VA_ARGS__);				\
    eri_assert (! eri_syscall_is_error (_res));				\
    _res;								\
  })

#define eri_assert_syscall_nr(...) \
  ({									\
    uint64_t _res = eri_syscall_nr (__VA_ARGS__);			\
    eri_assert (! eri_syscall_is_error (_res));				\
    _res;								\
  })

#define eri_sys_syscall(args) \
  ({ struct eri_sys_syscall_args *_a = args;				\
     _a->result = eri_syscall_nr (_a->nr, _a->a[0], _a->a[1], _a->a[2],	\
				  _a->a[3], _a->a[4], _a->a[5]); })

uint64_t eri_sys_clone (const struct eri_sys_clone_args *args);

#define eri_assert_sys_clone(args) \
  ({ uint64_t _res = eri_sys_clone (args);				\
     eri_assert (! eri_syscall_is_error (_res)); _res; })

void eri_assert_sys_sigreturn (void);

#define eri_assert_sys_sigaction(sig, act, old_act) \
  eri_assert_syscall (rt_sigaction, sig, act, old_act, ERI_SIG_SETSIZE)

#define eri_assert_sys_sigprocmask(mask, old_mask) \
  eri_assert_syscall (rt_sigprocmask, ERI_SIG_SETMASK,			\
		      mask, old_mask, ERI_SIG_SETSIZE)

void eri_assert_sys_futex_wake (void *mem, uint32_t val);
uint8_t eri_assert_sys_futex_wait (void *mem, uint32_t old_val,
				   const struct eri_timespec *timeout);

#endif
#endif
