'use strict'; /* vim: set ft=javascript: */

return [ 'basic', 'clone', 'clear-tid', 'raise', 'sig-ignore', 'sig-nest', 'sig-exit-group',
  'sig-sig-mask', 'sigprocmask', 'sig-sig-prepare-sync', 'single-step', 'sync-async',
  'sigaltstack', 'sigpending', 'sigsuspend', 'sigtimedwait', 'signalfd', 'io', 'mmap', 'stat',
  'link', 'getdents', 'chmod', 'uname' ].concat ([ ...Array (6).keys () ].map (x => `exit-${x}`));
