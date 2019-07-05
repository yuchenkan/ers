/* vim: set ft=c: */
m4_include(`m4/util.m4')

#include <lib/util.h>
#include <m4_syscall_h>
#include <m4_atomic_h>

uint64_t clone (int32_t flags, void *stack, int32_t *ptid,
		int32_t *ctid, void *new_tls);

uint64_t
m4_ns(sys_clone) (struct eri_sys_clone_args *args)
{
  void **stack = (void *) args->stack;
  *--stack = args->fn;
  *--stack = args->a0;
  *--stack = args->a1;
  *--stack = args->a2;
  return args->result = clone (args->flags, stack, args->ptid,
			       args->ctid, args->new_tls);
}

void
m4_ns(assert_sys_futex_wake) (void *mem, uint32_t val)
{
  uint32_t *p = mem;
  m4_ns(atomic_store) (p, val, 1);
  m4_ns(assert_syscall) (futex, p, ERI_FUTEX_WAKE, 1);
}

uint8_t
m4_ns(assert_sys_futex_wait) (void *mem, uint32_t old_val,
			      const struct eri_timespec *timeout)
{
  uint32_t *p = mem;
  while (m4_ns(atomic_load) (p, 1) == old_val)
    {
      uint64_t res = m4_ns(syscall) (futex, p, ERI_FUTEX_WAIT,
				     old_val, timeout);
      if (timeout && res == ERI_ETIMEDOUT) return 0;
      eri_assert (eri_syscall_is_ok (res)
		  || res == ERI_EAGAIN || res == ERI_EINTR);
    }
  return 1;
}
