'use strict'; /* vim: set ft=javascript: */

if (typeof srcs === 'undefined')
  var srcs = [ 'live/signal-thread.l', 'live/thread.c.o', 'live/thread-futex.c.o', 'live/common.c.o',
	       'live/tst/thread-recorder.c.o', 'common/common.a', 'lib/lib.a' ];
if (typeof keep === 'undefined')
  var keep = [ '^eri_live_signal_thread__init_main$', '^eri_global_enable_debug$' ];

await this.invoke ('tst/goal/main.l.g', { srcs, keep });
