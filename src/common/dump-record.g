'use strict'; /* vim: set ft=javascript: */

/* XXX: common/common.l lib/lib.a compiled with fPIC */
await this.invoke ('goal/link.g', { srcs: [ `${goal}.c.o`, 'common/common.l', 'lib/lib.a' ], ldflags: () => '' });
