#ifndef ERI_ANALYSIS_H
#define ERI_ANALYSIS_H

#include "lib/malloc.h"
#include "vex/vex-pub.h"

struct eri_analysis;
struct eri_analysis_thread;

struct eri_analysis *eri_analysis_create (struct eri_mtpool *pool,
					  int *printf_lock);
void eri_analysis_delete (struct eri_analysis *analysis);

struct eri_analysis_thread *eri_analysis_create_thread (struct eri_analysis *analysis,
							struct eri_analysis_thread *parent,
							unsigned long name);
void eri_analysis_delete_thread (struct eri_analysis_thread *th);

void eri_analysis_record (struct eri_analysis_thread *th, struct eri_vex_brk_desc *desc);

void eri_analysis_silence (struct eri_analysis_thread *th, char enter);
void eri_analysis_sync_acq (struct eri_analysis_thread *th,
			    unsigned long var, unsigned long ver);
void eri_analysis_sync_rel (struct eri_analysis_thread *th,
			    unsigned long var, unsigned long ver, unsigned long exit);

#endif
