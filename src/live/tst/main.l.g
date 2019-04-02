'use strict'; /* vim: set ft=javascript: */

if (typeof srcs === 'undefined')
  var srcs = [ 'live/signal-thread.l', 'live/thread.l', 'live/tst/thread-recorder.c.o',
	       'common/common.l', 'common/helper.c.o', 'lib/lib.a' ];
if (typeof keep === 'undefined')
  var keep = [ '^eri_live_signal_thread__init_main$', '^eri_global_enable_debug$' ];

await this.invoke ('goal/tst/main.l.g', { srcs, keep });
