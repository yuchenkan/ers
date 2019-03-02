'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${goal}.c.o` ].concat ([ 'tst/live-sig-hand-ut.l', 'tst/tst-common-start.S.o', 'lib.a' ]);
const script = 'tst/tst-live-sig-hand-ut.ld';
await this.invoke ('goal/link.g', { srcs, extra: [ script ], ldflags: (_, f) => `${f} -T ${script}` });
