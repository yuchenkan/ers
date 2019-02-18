'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'tst/tst-rtld.S.o' ];
await this.invoke ('goal/link.g', { srcs, ldflags: f => `${f} -pie -Wl,-e,start` });
