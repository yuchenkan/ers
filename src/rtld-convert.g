'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'rtld-convert.c.o' ];

await this.invoke ('goal/link.g', { srcs, ldflags: () => '' });
