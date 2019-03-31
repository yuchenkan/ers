'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'common/helper.c.o', 'replay/rtld.l', 'replay/thread.l',
	       'common/rtld.c.o', 'common/common.l', 'lib/lib.a' ];
const script = 'replay/replay.ld';
await this.invoke ('goal/link.g', {
  srcs, extra: [ script ], ldflags: f => `${f} -Wl,-T,${script} -Wl,-e,eri_start -pie`
});
