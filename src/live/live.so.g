'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'live/signal-thread.l', 'live/thread.c.o', 'live/thread-recorder.c.o',
	       'common/thread.l', 'common/serial.c.o', 'common/helper.c.o', 'lib/lib.a' ];
await this.invoke ('goal/link.g', { srcs, ldflags: f => `${f} -Wl,-e,eri_live_signal_thread__init_main -shared` });
