'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ ];

await this.invoke ('live/tst/tst-live.g', { extra: [ 'live/tst/tst-entry.c.o' ].concat (extra) });
