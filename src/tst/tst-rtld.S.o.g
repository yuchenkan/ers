'use strict'; /* vim: set ft=javascript: */

await this.invoke ('goal/compile.g', { cflags: f => f.replace ('-fPIC', '-fPIE') });
