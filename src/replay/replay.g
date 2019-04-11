'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ 'replay/thread.c.o' ];

const srcs = extra.concat ([ 'replay/rtld.l', 'common/rtld.c.o', 'common/thread.l', 'common/serial.c.o', 'common/helper.c.o', 'lib/lib.a' ]);
const script = 'replay/replay.ld';
await this.invoke ('goal/link.g', {
  srcs, extra: [ script ], ldflags: f => `${f} -Wl,-T,${script} -Wl,-e,eri_start -pie`
});
