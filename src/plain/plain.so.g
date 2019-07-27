'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'plain/thread.c.o', 'common/common.a', 'lib/lib.a' ];
await this.invoke ('goal/link.g', { srcs, ldflags: f => `${f} -Wl,-e,eri_plain_start -shared` });
