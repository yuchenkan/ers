'use strict'; /* vim: set ft=javascript: */

await this.invoke ('lib/syscall-specific.m4.g', {
  ns: 'tst_', syscall: 'ERS_SYSCALL (\\$1)', header: x => `tst/tst-${x}-specific.h`
});
