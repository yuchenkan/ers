'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'rand', 'lock' ].map (s => `tst/tst-${s}.c.o`).concat ([ 'tst/tst-syscall.l' ]);
await this.invoke ('goal/archive.g', { srcs });
