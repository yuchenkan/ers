'use strict'; /* vim: set ft=javascript: */

const extra = [ 'tst/rtld/recorder' ];
await this.invoke ('goal/tst/out.g', { extra, environ: 'ERS_RECORDER=rtld/recorder' });
