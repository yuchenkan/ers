'use strict'; /* vim: set ft=javascript: */

const script = 'goals/compile.g';
const cflags = f => `${f.replace ('-fPIC', '-fPIE')} -fdata-sections -ffunction-sections`;
await this.update ([ script ], async () => {
  await this.invoke (script, { cflags: cflags });
});
