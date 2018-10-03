#ifndef _ERS_RECORDER_COMMON_H
#define _ERS_RECORDER_COMMON_H

#include "lib/util-common.h"

#ifndef __ASSEMBLER__

#define ERS_LIVE	0
#define ERS_REPLAY	1
#define ERS_ANALYSIS	2

struct ers_recorder
{
  char (*init_process) (const char *path); /* return mode */
  /* The fs base address is deeply involved with tls, no try to
     change this value for now.  */
  void (*setup_tls) (long offset);

  long (*syscall) (int nr, long a1, long a2, long a3,
		   long a4, long a5, long a6);

  void (*atomic_lock) (void *mem);
  void (*atomic_unlock) (void *mem, int mo);
  void (*atomic_barrier) (int mo);

  void (*analysis) (unsigned long entry, unsigned long info,
		    unsigned long stack);
};

struct ers_recorder *ers_get_recorder (void);

struct ers_info
{
  const char *libname;
  struct ers_recorder *recorder;
};

#endif

#endif
