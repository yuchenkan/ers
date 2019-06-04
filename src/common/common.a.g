'use strict'; /* vim: set ft=javascript: */

const srcs = [ 'rtld', 'common', 'serial', 'helper' ].map (s => `common/${s}.c.o`).concat ([ 'common/thread.l' ]);
await this.invoke ('goal/archive.g', { srcs });
