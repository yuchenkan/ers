'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${env.trim (goal)}.S.o`, `${env.trim (goal)}.c.o`, 'lib/lib.a' ];
await this.invoke ('goal/link.g', { srcs, ldflags: f => `${f} -Wl,-e,eri_start -shared` });
