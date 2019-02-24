'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'tst/live.l', 'tst/tst-syscall.l', 'lib/tst-util.c.o', 'tst/tst-common-start.S.o', 'tst/tst-live-main.c.o' ];

await this.invoke ('goal/archive.g', { srcs });
