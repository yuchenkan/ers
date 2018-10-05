#ifndef ERI_ANALYSIS_H
#define ERI_ANALYSIS_H

#include "lib/malloc.h"
#include "vex/vex-pub.h"

struct eri_analysis;
struct eri_analysis_thread;

struct eri_analysis *eri_analysis_create (struct eri_mtpool *pool);
void eri_analysis_delete (struct eri_analysis *analysis);

struct eri_analysis_thread *eri_analysis_create_thread (struct eri_analysis *analysis, unsigned long id);
void eri_analysis_delete_thread (struct eri_analysis_thread *th);

void eri_analysis_record (struct eri_analysis_thread *th, struct eri_vex_brk_desc *desc);

void eri_analysis_silence (struct eri_analysis_thread *th, char enter);
void eri_analysis_sync (struct eri_analysis_thread *th, char acq, unsigned long var, unsigned long ver);

#endif
