'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'rtld', 'serial', 'helper' ].map (s => `common/${s}.c.o`).concat ([ 'common/entry.l', 'common/common.l' ]);
await this.invoke ('goal/archive.g', { srcs });
