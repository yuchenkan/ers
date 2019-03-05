'use strict'; /* vim: set ft=javascript: */

const lib = [ 'live/tst/sig-hand-ut.l', 'tst/tst-common-start.S.o', 'lib/lib.a' ];
const main = new Set ([ 'main', 'sig-action' ].map (x => `live/tst/tst-sig-hand-${x}-ut`)).has (goal);
const extra = ! main ? [ 'live/tst/tst-sig-hand-ut.c.o' ] : [ ];
const srcs = [ `${goal}.c.o` ].concat (extra).concat (lib);
const script = `live/tst/tst-sig-hand-ut.ld`;
await this.invoke ('goal/link.g', { srcs, extra: [ script ], ldflags: (_, f) => `${f} -T ${script}` });
