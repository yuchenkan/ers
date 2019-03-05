'use strict'; /* vim: set ft=javascript: */

const extra = [ 'live/tst/rtld/live' ];
await this.invoke ('goal/tst/out.g', { extra, environ: 'ERS_LIVE=rtld/live' });
