#ifndef ERI_LIVE_DEBUG_H
#define ERI_LIVE_DEBUG_H

#include <stdint.h>

#include <common/debug.h>

#define eri_live_debug(log, fmt, ...) \
  do {									\
    typeof (log) _log = log;						\
    uint32_t _flags = ERI_DEBUG_PCTX					\
		| (eri_global_enable_debug == 2 ? ERI_DEBUG_TEE : 0);	\
    eri_fdebug (!! _log, log, _flags, fmt, ##__VA_ARGS__);		\
  } while (0)

#endif
