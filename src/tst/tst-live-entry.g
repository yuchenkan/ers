'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ ];

await this.invoke ('tst/tst-live.g', { extra: [ 'tst/tst-live-entry.c.o' ].concat (extra) });
