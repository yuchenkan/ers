'use strict'; /* vim: set ft=javascript: */

await this.invoke (`lib/specific.m4.g`, { ns: 'tst_', header: x => `tst/tst-${x}-specific.h` });
