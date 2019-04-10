#ifndef ERI_COMMON_THREAD_LOCAL_H
#define ERI_COMMON_THREAD_LOCAL_H

#include <stdint.h>

#include <lib/compiler.h>

struct eri_sigframe;

extern uint8_t th_text[];
extern uint8_t th_text_end[];

extern uint8_t th_text_enter[];
extern uint8_t th_text_leave[];

eri_noreturn void enter (void);
void sig_return_back (struct eri_sigframe *frame);
eri_noreturn void sig_op_ret (struct eri_entry *entry,
			      struct eri_sigframe *frame);

eri_noreturn void sig_action (struct eri_entry *entry);

#endif
