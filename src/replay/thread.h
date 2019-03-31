#ifndef ERI_REPLAY_THREAD_H
#define ERI_REPLAY_THREAD_H

#include <lib/compiler.h>

struct eri_replay_rtld_args;

eri_noreturn void eri_replay_start (struct eri_replay_rtld_args *rtld_args);

#endif
