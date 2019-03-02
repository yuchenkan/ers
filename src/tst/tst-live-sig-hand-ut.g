'use strict'; /* vim: set ft=javascript: */

const lib = [ 'tst/live-sig-hand-ut.l', 'tst/tst-common-start.S.o', 'lib.a' ];
const extra = goal !== 'tst/tst-live-sig-hand-main-ut' ? [ 'tst/tst-live-sig-hand-ut.c.o' ] : [ ];
const srcs = [ `${goal}.c.o` ].concat (extra).concat (lib);
const script = `tst/tst-live-sig-hand-ut.ld`;
await this.invoke ('goal/link.g', { srcs, extra: [ script ], ldflags: (_, f) => `${f} -T ${script}` });
