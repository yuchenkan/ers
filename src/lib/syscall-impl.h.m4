/* vim: set ft=cpp: */
m4_include(`m4/util.m4')

#ifndef m4_NS(LIB_SYSCALL_IMPL_H)
#define m4_NS(LIB_SYSCALL_IMPL_H)

#include <lib/compiler.h>
#include <lib/util.h>
#include <lib/syscall-common.h>

#ifndef __ASSEMBLER__
#include <stdint.h>

#define m4_ns(syscall_nr, _)(nr, nargs, ...) \
  ({									\
    uint64_t __res;							\
    ERI_PP_FOREACH (_ERI_LOAD_ARG, (_), ##__VA_ARGS__)			\
    ERI_PP_FOREACH (_ERI_LOAD_REG, (_), ##__VA_ARGS__)			\
    asm volatile (							\
      ERI_STR (m4_syscall(1))						\
      : "=a" (__res)							\
      : "0" (nr) ERI_PP_FOREACH (_ERI_SYSCALL_ARG, (_), ##__VA_ARGS__)	\
      : "memory", "r11", "cx"						\
    );									\
    __res;								\
  })

#define m4_ns(syscall)(name, ...) \
  m4_ns(syscall_nr, _) (__NR_##name,					\
			ERI_PP_NARGS (__VA_ARGS__), ##__VA_ARGS__)

#define m4_ns(syscall_nr)(nr, ...) \
  m4_ns(syscall_nr, _) (nr, ERI_PP_NARGS (__VA_ARGS__), ##__VA_ARGS__)

#define m4_ns(assert_syscall)(...) \
  ({									\
    uint64_t _res = m4_ns(syscall) (__VA_ARGS__);			\
    eri_assert (eri_syscall_is_ok (_res));				\
    _res;								\
  })

#define m4_ns(assert_syscall_nr)(...) \
  ({									\
    uint64_t _res = m4_ns(syscall_nr) (__VA_ARGS__);			\
    eri_assert (eri_syscall_is_ok (_res));				\
    _res;								\
  })

static eri_unused uint64_t
m4_ns(sys_syscall) (struct eri_sys_syscall_args *a)
{
  return a->result = m4_ns(syscall_nr) (a->nr, a->a[0], a->a[1], a->a[2],
					a->a[3], a->a[4], a->a[5]);
}

uint64_t m4_ns(sys_clone) (struct eri_sys_clone_args *args);

#define m4_ns(assert_sys_clone)(args) \
  ({ uint64_t _res = m4_ns(sys_clone) (args);				\
     eri_assert (eri_syscall_is_ok (_res)); _res; })

eri_noreturn void m4_ns(assert_sys_sigreturn) (void);

#define m4_ns(assert_sys_sigaction)(sig, act, old_act) \
  m4_ns(assert_syscall) (rt_sigaction, sig, act, old_act, ERI_SIG_SETSIZE)

#define m4_ns(assert_sys_sigprocmask)(mask, old_mask) \
  m4_ns(assert_syscall) (rt_sigprocmask, ERI_SIG_SETMASK,		\
			 mask, old_mask, ERI_SIG_SETSIZE)

void m4_ns(assert_sys_futex_wake) (void *mem, uint32_t val);
uint8_t m4_ns(assert_sys_futex_wait) (void *mem, uint32_t old_val,
				      const struct eri_timespec *timeout);

eri_noreturn void m4_ns(assert_sys_thread_die) (int32_t *alive);

#define m4_ns(assert_sys_exit)(status) \
  do { m4_ns(assert_syscall (exit, status));				\
       eri_assert_unreachable (); } while (0)

#define m4_ns(assert_sys_exit_group)(status) \
  do { m4_ns(assert_syscall (exit_group, status));			\
       eri_assert_unreachable (); } while (0)

#define m4_ns(assert_sys_exit_nr)(nr, status) \
  do { m4_ns(assert_syscall_nr (nr, status));				\
       eri_assert_unreachable (); } while (0)

static eri_unused uint64_t
m4_ns(sys_open) (const char *path, uint8_t read)
{
  return m4_ns(syscall) (open, path,
	read ? ERI_O_RDONLY : ERI_O_WRONLY | ERI_O_TRUNC | ERI_O_CREAT,
	ERI_S_IRUSR | ERI_S_IWUSR);
}
#define m4_ns(assert_sys_open)(path, read) \
  ({ uint64_t _res = m4_ns(sys_open) (path, read);			\
     eri_assert (eri_syscall_is_ok (_res)); _res; })

#define m4_ns(assert_sys_read)(fd, buf, size) \
  do {									\
    int32_t _fd = fd;							\
    uint8_t *_buf = (void *) buf;					\
    uint64_t _size = size;						\
    uint8_t *_end = _buf + _size;					\
    while (_buf != _end)						\
      {									\
	uint64_t _res = m4_ns(syscall) (read, _fd, _buf, _end - _buf);	\
	if (_res == ERI_EINTR) continue;				\
	eri_assert (eri_syscall_is_ok (_res) && _res);			\
	_buf += _res;							\
      }									\
  } while (0)

#define m4_ns(assert_sys_write)(fd, buf, size) \
  do {									\
    int32_t _fd = fd;							\
    uint8_t *_buf = (void *) buf;					\
    uint64_t _size = size;						\
    uint8_t *_end = _buf + _size;					\
    while (_buf != _end)						\
      {									\
	uint64_t _res = m4_ns(syscall) (write, _fd, _buf, _end - _buf);	\
	if (_res == ERI_EINTR) continue;				\
	eri_assert (eri_syscall_is_ok (_res));				\
	_buf += _res;							\
      }									\
  } while (0)

#define m4_ns(assert_sys_mkdir)(path, mode) \
  do { uint64_t _res = m4_ns(syscall) (mkdir, path, mode);		\
       eri_assert (_res == ERI_EEXIST					\
		   || eri_syscall_is_ok (_res)); } while (0)

#endif

#endif
