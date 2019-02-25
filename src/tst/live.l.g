'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'common.c.o', 'live-signal-thread.l', 'live-thread.l', 'helper.c.o', 'live-thread-recorder.c.o', 'lib.a' ];
const keep = [ 'eri_live_signal_thread_init_main', 'eri_global_enable_debug' ].map (s => `^${s}$`).join ('\\|');

await this.invoke ('goal/local.g', { srcs, keep, ldflags: '--no-undefined --fatal-warnings' });
/* XXX: Assert number of sections to avoid new unknown section.  */
await env.run (`(($(objdump -h ${goal} | wc -l) == 39))`);
