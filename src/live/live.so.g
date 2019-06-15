'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'live/signal-thread.l', 'live/thread.c.o', 'live/thread-recorder.c.o', 'live/common.c.o',
	       'common/common.a', 'lib/lib.a' ];
await this.invoke ('goal/link.g', { srcs, ldflags: f => `${f} -Wl,-e,eri_live_signal_thread__init_main -shared` });
