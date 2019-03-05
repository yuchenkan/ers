'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'live/signal-thread.l', 'live/thread.l', 'live/thread-recorder.c.o',
	       'common.c.o', 'helper.c.o', 'lib/lib.a' ];
await this.invoke ('goal/link.g', { srcs, ldflags: f => `-Wl,-e,eri_live_signal_thread__init_main -shared` });
