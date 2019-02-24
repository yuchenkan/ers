'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ ];

const srcs = [ `${goal}.c.o`, 'tst/tst-live.a', 'lib.a' ].concat (extra);
await this.invoke ('goal/link.g', { srcs, ldflags: (_, f) => f });
