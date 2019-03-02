#ifndef ERI_HELPER_H
#define ERI_HELPER_H

#include <stdint.h>

struct eri_mtpool;
struct eri_siginfo;
struct eri_ucontext;

struct eri_helper;

struct eri_helper *eri_helper__start (struct eri_mtpool *pool,
				     uint64_t stack_size, int32_t pid);
void eri_helper__exit (struct eri_helper *helper);

typedef void (*eri_helper__sigsegv_handler_t) (struct eri_siginfo *info,
					       struct eri_ucontext *ctx);
void eri_helper__invoke (struct eri_helper *helper, void (*fn) (void *),
			 void *args, eri_helper__sigsegv_handler_t segv_hand);
int32_t eri_helper__get_pid (const struct eri_helper *helper);

#endif
