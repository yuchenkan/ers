'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${goal}.c.o` ];

await this.invoke ('goal/link.g', { srcs, ldflags: () => '' });
