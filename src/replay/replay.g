'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ 'replay/thread.c.o' ];

const srcs = extra.concat ([ 'replay/rtld.l', 'common/common.a', 'lib/lib.a' ]);
const script = 'replay/replay.ld';
await this.invoke ('goal/link.g', {
  srcs, extra: [ script ], ldflags: f => `${f} -Wl,-T,${script} -Wl,-e,eri_start -pie`
});
