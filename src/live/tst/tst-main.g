'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ ];

const srcs = [ `${goal.replace('/tst-main-', '/tst-')}.c.o` ].concat (extra).concat ([ 'live/tst/tst-main.a', 'lib/lib.a' ]);
const script = 'live/tst/tst-main.ld';
await this.invoke ('goal/link.g', { srcs, extra: [ script ], ldflags: (_, f) => `${f} -T ${script}` });
