#ifndef ERI_PLAIN_THREAD_H
#define ERI_PLAIN_THREAD_H

#include <lib/compiler.h>

struct eri_live_rtld_args;

eri_noreturn void eri_plain_start (
		struct eri_live_rtld_args *rtld_args);

#endif
