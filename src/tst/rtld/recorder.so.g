'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'tst/rtld/recorder.S.o', 'tst/rtld/recorder.c.o', 'lib.a' ];
await this.invoke ('goal/link.g', { srcs, ldflags: (_, f) => `${f} -shared` });
