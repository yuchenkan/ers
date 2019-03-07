'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'live/tst/live.l', 'tst/tst-syscall.l', 'tst/tst-rand.c.o', 'tst/tst-start.S.o',
	       'live/tst/tst-main.c.o', 'live/tst/tst-syscall.c.o' ];

await this.invoke ('goal/archive.g', { srcs });
