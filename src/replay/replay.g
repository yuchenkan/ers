'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'rtld.c.o', 'common.c.o', 'helper.c.o', 'replay/rtld.l', 'replay/thread.l', 'lib/lib.a' ];
const script = 'replay/replay.ld';
await this.invoke ('goal/link.g', {
  srcs, extra: [ script ], ldflags: f => `${f} -Wl,-T,${script} -Wl,-e,eri_start`
});
