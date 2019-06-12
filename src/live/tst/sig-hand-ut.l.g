'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'live/thread.c.o', `live/tst/sig-hand-ut.c.o`, 'live/tst/thread-recorder.c.o',
	       'common/entry.l', 'lib/lib.a' ];
const keep = [ '^eri_live_thread__.*', '^eri_global_enable_debug$' ];

await this.invoke ('live/tst/main.l.g', { srcs, keep });
