'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'common.c.o', 'live/thread.l', `live/tst/sig-hand-ut.c.o`,
	       'live/tst/thread-recorder.c.o', 'lib/lib.a' ];
const keep = [ '^eri_live_thread__.*', '^eri_global_enable_debug$' ];

await this.invoke ('live/tst/live.l.g', { srcs, keep });
