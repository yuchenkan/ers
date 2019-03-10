'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'rtld.c.o', 'replay/rtld.l', 'replay/replay.c.o', 'lib/lib.a' ];
const script = 'replay/replay.ld';
await this.invoke ('goal/link.g', {
  srcs, extra: [ script ], ldflags: f => `${f} -Wl,-T,${script} -Wl,-e,eri_start`
});
