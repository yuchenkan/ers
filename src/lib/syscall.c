#include "compiler.h"

#include "lib/atomic.h"
#include "lib/syscall.h"

uint64_t clone (int32_t flags, void *stack, int32_t *ptid,
		int32_t *ctid, void *new_tls);

uint64_t
eri_sys_clone (const struct eri_sys_clone_args *args)
{
  void **stack = (void *) args->stack;
  *--stack = args->fn;
  *--stack = args->a0;
  *--stack = args->a1;
  *--stack = args->a2;
  return clone (args->flags, stack, args->ptid,
		args->ctid, args->new_tls);
}

void
eri_assert_sys_futex_wake (void *mem, uint32_t val)
{
  uint32_t *p = mem;
  eri_atomic_store_rel (p, val);
  eri_assert_syscall (futex, p, ERI_FUTEX_WAKE, 1);
}

uint8_t
eri_assert_sys_futex_wait (void *mem, uint32_t old_val,
			   const struct eri_timespec *timeout)
{
  uint32_t *p = mem;
  while (eri_atomic_load_acq (p) == old_val)
    {
      uint64_t res = eri_syscall (futex, p, ERI_FUTEX_WAIT,
				  old_val, timeout);
      if (timeout && res == ERI_ETIMEDOUT) return 0;
      eri_assert (! eri_syscall_is_error (res) || res == ERI_EAGAIN);
    }
  return 1;
}
