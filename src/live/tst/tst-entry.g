'use strict'; /* vim: set ft=javascript: */

if (typeof extra === 'undefined') var extra = [ ];

await this.invoke (`${goal.match (/^(live\/tst\/tst-[^.-]*)-entry-/)[1]}.g`, { extra: [ 'live/tst/tst-entry.c.o' ].concat (extra) });
