#ifndef ERI_COMMON_H
#define ERI_COMMON_H

#include <stdint.h>
#include <lib/util.h>
#include <lib/lock.h>
#include <lib/syscall-common.h>

struct eri_common_args
{
  //const char *config;
  const char *path;

  uint64_t stack_size;
  uint64_t file_buf_size;
};

#define eri_init_mtpool_from_buf(buf, size, exec) \
  ({									\
    uint8_t *_buf = (void *) buf;					\
    uint64_t _size = size;						\
    eri_assert_syscall (mmap, _buf, _size,				\
	/* XXX: exec security */					\
	ERI_PROT_READ | ERI_PROT_WRITE | ((exec) ? ERI_PROT_EXEC : 0),	\
	ERI_MAP_FIXED | ERI_MAP_PRIVATE | ERI_MAP_ANONYMOUS, -1, 0);	\
									\
    struct eri_mtpool *_pool = (void *) _buf;				\
    uint64_t _pool_size = eri_size_of (*_pool, 16);			\
    eri_assert (_size >= _pool_size);					\
    eri_assert_init_mtpool (_pool, _buf + _pool_size,			\
			    _size - _pool_size);			\
    _pool;								\
  })

#define eri_build_path_len(path, name, id) \
  (eri_strlen (path) + 1 + eri_strlen (name) + eri_itoa_size (id))

void eri_build_path (const char *path, const char *name,
		     uint64_t id, char *buf);

void eri_mkdir (const char *path);

struct eri_sig_act
{
  struct eri_lock lock;
  struct eri_sigaction act;
};

void eri_sig_init_acts (struct eri_sig_act *sig_acts, eri_sig_handler_t hand);
void eri_sig_get_act (struct eri_sig_act *sig_acts, int32_t sig,
		      struct eri_sigaction *act);
void eri_sig_set_act (struct eri_sig_act *sig_acts, int32_t sig,
		      const struct eri_sigaction *act,
		      struct eri_sigaction *old_act);

#define eri_atomic_slot(mem)		((mem) & ~0xf)
#define eri_atomic_slot2(mem, size)	eri_atomic_slot ((mem) + (size) - 1)

#define eri_atomic_cross_slot(mem, size) \
  ({ uint64_t _mem = mem;						\
     eri_atomic_slot (_mem) != eri_atomic_slot2 (_mem, size); })

#include <compiler.h>
#include <lib/printf.h>
#include <lib/syscall.h>

#define _eri_log(level, fmt, ...) \
  eri_assert_printf ("[" ERI_STR (level) " %s:%u(%s)%lu]\t" fmt,	\
		     __FILE__, __LINE__, __FUNCTION__,			\
		     eri_assert_syscall (gettid), ##__VA_ARGS__)

static eri_unused uint8_t eri_enable_debug = 0;
extern uint8_t eri_global_enable_debug;
#define eri_debug(fmt, ...) \
  do {									\
    if (eri_enable_debug || eri_global_enable_debug)			\
      _eri_log (DEBUG, fmt, ##__VA_ARGS__);				\
  } while (0)

#define eri_info(fmt, ...)	_eri_log (INFO, fmt, ##__VA_ARGS__)

#define eri_debug_stop() \
  eri_assert_syscall (kill, eri_assert_syscall (getpid), ERI_SIGSTOP)

#define eri_dump_maps() \
  do {									\
    eri_file_t _file;							\
    uint8_t _buf[1024];							\
    eri_assert_fopen ("/proc/self/maps", 1, &_file, 0, 0);		\
    uint64_t _len;							\
    do									\
      {									\
        eri_assert_fread (_file, _buf, sizeof _buf, &_len);		\
        eri_assert_fwrite (ERI_STDOUT, _buf, _len, 0);			\
      }									\
    while (_len == sizeof _buf);					\
  } while (0)

#endif
