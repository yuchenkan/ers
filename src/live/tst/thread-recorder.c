#include <lib/util.h>
#include <live/tst/tst-util.h>

#define BLANK_ZERO(func) \
TST_WEAK_BLANK_ZERO (ERI_PASTE (eri_live_thread_recorder__, func))
#define BLANK(func) \
TST_WEAK_BLANK (ERI_PASTE (eri_live_thread_recorder__, func))

BLANK_ZERO (create_group);
BLANK (destroy_group);
BLANK_ZERO (create);
BLANK (destroy);
BLANK (rec_init);
BLANK (rec_signal);
BLANK (rec_syscall_restart_out);
BLANK (rec_syscall_getrandom);
BLANK (rec_syscall_read);
BLANK (rec_syscall_mmap);
BLANK (rec_syscall_getcwd);
BLANK (rec_syscall);
BLANK (rec_sync_async);
BLANK (rec_restart_sync_async);
BLANK (rec_atomic);
BLANK (rec_atomic_load);
