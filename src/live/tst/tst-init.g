'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ ];

const srcs = [ `${goal.replace('/tst-init-', '/tst-')}.c.o`, 'live/tst/tst-start.S.o',
  'live/tst/tst-syscall.c.o', 'tst/tst-lib.a', 'common/common.l' ].concat (extra).concat ([ 'lib/lib.a' ]);
await this.invoke ('goal/link.g', { srcs, ldflags: (_, f) => f });
