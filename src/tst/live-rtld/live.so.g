'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${env.trim (goal)}.S.o`, `${env.trim (goal)}.c.o`, 'lib.a' ];
await this.invoke ('goal/link.g', { srcs, ldflags: f => `-Wl,-e,eri_start -shared` });
