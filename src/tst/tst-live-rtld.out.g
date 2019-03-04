'use strict'; /* vim: set ft=javascript: */

const extra = [ 'tst/live-rtld/live' ];
await this.invoke ('goal/tst/out.g', { extra, environ: 'ERS_LIVE=live-rtld/live' });
