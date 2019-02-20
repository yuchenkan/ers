/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#ifndef m4_format(`%sLIB_SYSCALL_DEDICATED_H', m4_upcase(m4_namespace))
#define m4_format(`%sLIB_SYSCALL_DEDICATED_H', m4_upcase(m4_namespace))

#include "compiler.h"
#include "lib/syscall-common.h"

#ifndef __ASSEMBLER__
#include <stdint.h>

#define m4_ns(syscall_nr, _)(nr, nargs, ...) \
  ({									\
    uint64_t __res;							\
    ERI_PASTE (_ERI_LOAD_ARGS_, nargs) (__VA_ARGS__)			\
    asm volatile (							\
      ERI_STR (m4_syscall(1))						\
      : "=a" (__res)							\
      : "0" (nr) ERI_PASTE (_ERI_SYSCALL_ARGS_, nargs)			\
      : "memory", "cc", "r11", "cx"					\
    );									\
    __res;								\
  })

#define m4_ns(syscall)(name, ...) \
  m4_ns(syscall_nr, _) (__NR_##name,					\
			eri_syscall_nargs (0, ##__VA_ARGS__), 		\
			##__VA_ARGS__)

#define m4_ns(syscall_nr)(nr, ...) \
  m4_ns(syscall_nr, _) (nr, eri_syscall_nargs (0, ##__VA_ARGS__),	\
			##__VA_ARGS__)

#define m4_ns(assert_syscall)(...) \
  ({									\
    uint64_t _res = m4_ns(syscall) (__VA_ARGS__);			\
    eri_assert (! eri_syscall_is_error (_res));				\
    _res;								\
  })

#define m4_ns(assert_syscall_nr)(...) \
  ({									\
    uint64_t _res = m4_ns(syscall_nr) (__VA_ARGS__);			\
    eri_assert (! eri_syscall_is_error (_res));				\
    _res;								\
  })

#define m4_ns(sys_syscall)(args) \
  ({ struct eri_sys_syscall_args *_a = args;				\
     _a->result = m4_ns(syscall_nr) (_a->nr, _a->a[0], _a->a[1],	\
			_a->a[2], _a->a[3], _a->a[4], _a->a[5]); })

uint64_t m4_ns(sys_clone) (struct eri_sys_clone_args *args);

#define m4_ns(assert_sys_clone)(args) \
  ({ uint64_t _res = m4_ns(sys_clone) (args);				\
     eri_assert (! eri_syscall_is_error (_res)); _res; })

noreturn void m4_ns(assert_sys_sigreturn) (void);

#define m4_ns(assert_sys_sigaction)(sig, act, old_act) \
  m4_ns(assert_syscall) (rt_sigaction, sig, act, old_act, ERI_SIG_SETSIZE)

#define m4_ns(assert_sys_sigprocmask)(mask, old_mask) \
  m4_ns(assert_syscall) (rt_sigprocmask, ERI_SIG_SETMASK,		\
			 mask, old_mask, ERI_SIG_SETSIZE)

void m4_ns(assert_sys_futex_wake) (void *mem, uint32_t val);
uint8_t m4_ns(assert_sys_futex_wait) (void *mem, uint32_t old_val,
				      const struct eri_timespec *timeout);

#endif
#endif
