'use strict'; /* vim: set ft=javascript: */

/* XXX: common.l lib/lib.a compiled with fPIC */
await this.invoke ('goal/link.g', { srcs: [ `${goal}.c.o`, 'common.l', 'lib/lib.a' ], ldflags: () => '' });
