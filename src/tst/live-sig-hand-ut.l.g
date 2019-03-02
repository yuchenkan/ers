'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'common.c.o', 'live-thread.l', 'tst/live-sig-hand-async-ut.c.o',
	       'tst/live-thread-recorder.c.o', 'lib.a' ];
const keep = [ '^eri_live_thread__.*', '^eri_global_enable_debug$' ];

await this.invoke ('tst/live.l.g', { srcs, keep });
