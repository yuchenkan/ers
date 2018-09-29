#ifndef ERS_RECORDER_COMMON_H
#define ERS_RECORDER_COMMON_H

#define ERS_NONE
#define ERS_OMIT(...)

#define _ERS_STR_I(...) #__VA_ARGS__
#define _ERS_STR(...) _ERS_STR_I (__VA_ARGS__)

#define _ERS_EVAL(...) __VA_ARGS__

#define _ERS_PP_IF_0(...)
#define _ERS_PP_IF_1(...) __VA_ARGS__
#define _ERS_PP_IF_I(c, ...) _ERS_PP_IF_##c (__VA_ARGS__)
#define _ERS_PP_IF(c, ...) _ERS_PP_IF_I (c, __VA_ARGS__)

#define _ERS_PP_NOT_0 1
#define _ERS_PP_NOT_1 0
#define _ERS_PP_NOT_I(x) _ERS_PP_NOT_##x
#define _ERS_PP_NOT(x) _ERS_PP_NOT_I (x)

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
