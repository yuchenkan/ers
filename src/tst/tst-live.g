'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ ];

const srcs = [ `${goal}.c.o` ].concat (extra).concat ([ 'tst/tst-live.a', 'lib.a' ]);
const script = 'tst/tst-live.ld';
await this.invoke ('goal/link.g', { srcs, extra: [ script ], ldflags: (_, f) => `${f} -T ${script}` });
