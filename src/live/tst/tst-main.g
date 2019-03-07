'use strict'; /* vim: set ft=javascript: */

if (typeof src === 'undefined') var src = `${goal.replace('/tst-main-', '/tst-')}.c.o`;
if (typeof extra === 'undefined') var extra = [ ];

const srcs = [ src ].concat (extra).concat ([ 'live/tst/tst-main.a', 'lib/lib.a' ]);
const script = 'live/tst/tst-main.ld';
await this.invoke ('goal/link.g', { srcs, extra: [ script ], ldflags: (_, f) => `${f} -T ${script}` });
