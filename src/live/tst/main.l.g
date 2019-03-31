'use strict'; /* vim: set ft=javascript: */

if (typeof srcs === 'undefined')
  var srcs = [ 'live/signal-thread.l', 'live/thread.l', 'live/tst/thread-recorder.c.o',
	       'common/common.l', 'common/helper.c.o', 'lib/lib.a' ];
if (typeof keep === 'undefined')
  var keep = [ '^eri_live_signal_thread__init_main$', '^eri_global_enable_debug$' ];

await this.invoke ('goal/local.g', { srcs, keep });
await env.run (`(($(nm -u ${goal} | grep -v _GLOBAL_OFFSET_TABLE_ | awk '{ print; print >"/dev/stderr" }' | wc -l) == 0))`);
/* XXX: Assert number of sections to avoid new unknown section.  */
await env.run (`(($(objdump -h ${goal} | wc -l) == 39))`);
