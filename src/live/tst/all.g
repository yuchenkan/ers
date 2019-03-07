'use strict'; /* vim: set ft=javascript: */

let tsts = [ 'rtld', 'sig-mask-async-ut' ];
tsts = tsts.concat ([ 'basic', 'clone', 'clear-tid', 'raise', 'sig-ignore', 'sig-nest',
  'sig-exit-group', 'sig-sig-mask', 'sig-sig-prepare-sync',
  'sigaltstack', 'sigprocmask', 'sigpending', 'sigsuspend', 'sigtimedwait', 'signalfd' ].map (t => `main-${t}`));

tsts = tsts.concat ([ 'main', 'syscall', 'sync-async', 'atomic', 'atomic-ext', 'sig-action' ].map (x => `sig-hand-${x}-ut`));

tsts = tsts.concat ([ ...Array (6).keys () ].map (x => `main-exit-${x}`));

let entries = [ 'syscall', 'sync-async', 'sync-async-repeat' ];
entries = entries.concat ([ 'load', 'store', 'inc-dec', 'xchg', 'cmpxchg', 'cmp' ].map (x => `atomic-${x}`));

tsts = tsts.concat (entries.map (t => `main-entry-${t}`));

await this.update ([ 'live/tst/loop.sh' ].concat (tsts.map (t => `live/tst/tst-${t}.out`)));

//await this.update ([ 'tst/tst-live-sig-hand-sig-action-ut.out' ]);
