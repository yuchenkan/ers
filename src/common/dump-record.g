'use strict'; /* vim: set ft=javascript: */

/* XXX: common/serial.c.o lib/lib.a compiled with fPIC */
await this.invoke ('goal/link.g', { srcs: [ `${goal}.c.o`, 'common/serial.c.o', 'lib/lib.a' ], ldflags: () => '' });
