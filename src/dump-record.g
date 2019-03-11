'use strict'; /* vim: set ft=javascript: */

await this.invoke ('goal/link.g', { srcs: [ `${goal}.c.o` ], ldflags: () => '' });
