#ifndef ERI_HELPER_H
#define ERI_HELPER_H

#include <stdint.h>

struct eri_mtpool;
struct eri_siginfo;
struct eri_ucontext;

struct eri_helper;

/* Call with all signal masked.  */
struct eri_helper *eri_helper__start (
			struct eri_mtpool *pool, uint64_t stack_size,
			uint8_t selector, int32_t pid);
void eri_helper__exit (struct eri_helper *helper);

void eri_helper__invoke (struct eri_helper *helper, void (*fn) (void *),
			 void *args, eri_sig_handler_t hand);

void eri_helper__sig_unmask (struct eri_helper *helper);
/* Call with all signal masked.  */
uint8_t eri_helper__select_sig_handler (
		uint8_t selector,
		struct eri_siginfo *info, struct eri_ucontext *ctx);

int32_t eri_helper__get_pid (const struct eri_helper *helper);

#endif
