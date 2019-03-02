'use strict'; /* vim: set ft=javascript: */

const srcs = [ `${goal}.c.o` ].concat ([ `${goal.replace ('tst-', '')}.l`, 'tst/tst-common-start.S.o', 'tst/tst-syscall.S.o', 'lib.a' ]);
const script = `${goal}.ld`;
await this.invoke ('goal/link.g', { srcs, extra: [ script ], ldflags: (_, f) => `${f} -T ${script}` });
