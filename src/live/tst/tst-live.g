'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ ];

const srcs = [ `${goal}.c.o` ].concat (extra).concat ([ 'live/tst/tst-live.a', 'lib/lib.a' ]);
const script = 'live/tst/tst-live.ld';
await this.invoke ('goal/link.g', { srcs, extra: [ script ], ldflags: (_, f) => `${f} -T ${script}` });
