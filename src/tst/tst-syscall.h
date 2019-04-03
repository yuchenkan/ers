#ifndef TST_TST_TST_SYSCALL_H
#define TST_TST_TST_SYSCALL_H

#include <public/public.h>
#include <tst/tst-syscall-specific.h>

#define tst_stack_top(stack)		((stack) + sizeof (stack) - 8)

#endif
