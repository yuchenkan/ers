'use strict'; /* vim: set ft=javascript: */

const src = 'tst/tst-live-exit';
const args = goal.match (/^tst\/tst-live-exit-([^.]*).out$/)[1];
await this.invoke ('goal/tst/out.g', { src, args });
