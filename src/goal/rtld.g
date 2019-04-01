'use strict'; /* vim: set ft=javascript: */

const cflags = f => `${f} -fdata-sections -ffunction-sections`;
await this.invoke ('goal/compile.g', { cflags });
