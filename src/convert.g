'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'convert-common.c.o', `${goal}.c.o` ];

await this.invoke ('goal/link.g', { srcs, ldflags: () => '' });
