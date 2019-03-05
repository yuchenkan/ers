'use strict'; /* vim: set ft=javascript: */

const src = 'live/tst/tst-exit';
const args = goal.match (/^live\/tst\/tst-exit-([^.]*).out$/)[1];
await this.invoke ('goal/tst/out.g', { src, args });
