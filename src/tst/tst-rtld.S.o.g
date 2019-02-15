'use strict'; /* vim: set ft=javascript: */

const script = 'goals/compile.g';
await this.update ([ script ], async () => {
  await this.invoke (script, { cflags: f => f.replace ('-fPIC', '-fPIE') });
});
