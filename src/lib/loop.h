#ifndef ERI_LIB_LOOP_H
#define ERI_LIB_LOOP_H

#include <stdint.h>

#include "lib/malloc.h"

struct eri_loop;

struct eri_loop *eri_loop_create (uint8_t mt, struct eri_mtpool *pool);
void *eri_loop_loop (struct eri_loop *l);
void eri_loop_exit (struct eri_loop *l, void *data);

void eri_loop_trigger (struct eri_loop *l, void (*fn) (void *), void *data);

#endif
