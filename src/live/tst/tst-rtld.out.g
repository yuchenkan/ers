'use strict'; /* vim: set ft=javascript: */

const extra = [ 'live/tst/rtld/live' ];
await this.invoke ('tst/goal/out.g', { extra, environ: 'ERS_LIVE=rtld/live ERS_DATA=' });
