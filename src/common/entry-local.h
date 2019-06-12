#ifndef ERI_COMMON_ENTRY_LOCAL_H
#define ERI_COMMON_ENTRY_LOCAL_H

#include <stdint.h>

#include <lib/compiler.h>

struct eri_sigframe;

extern uint8_t th_text[];
extern uint8_t th_text_end[];

extern uint8_t th_text_enter[];
extern uint8_t th_text_leave[];

eri_noreturn void enter (void);
eri_noreturn void leave (struct eri_entry *entry);
void sig_return_back (struct eri_sigframe *frame);

#endif
