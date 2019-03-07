'use strict'; /* vim: set ft=javascript: */

let tsts = [ 'rtld', 'sig-mask-async-ut' ];
tsts = tsts.concat ([ 'main', 'syscall', 'sync-async', 'atomic', 'atomic-ext', 'sig-action' ].map (x => `sig-hand-${x}-ut`));

let commons = [ 'basic', 'clone', 'clear-tid', 'raise', 'sig-ignore', 'sig-nest',
  'sig-exit-group', 'sig-sig-mask', 'sig-sig-prepare-sync',
  'sigaltstack', 'sigprocmask', 'sigpending', 'sigsuspend', 'sigtimedwait', 'signalfd' ];
commons = commons.concat ([ ...Array (6).keys () ].map (x => `exit-${x}`));

let entries = [ 'syscall', 'sync-async', 'sync-async-repeat' ];
entries = entries.concat ([ 'load', 'store', 'inc-dec', 'xchg', 'cmpxchg', 'cmp' ].map (x => `atomic-${x}`));

commons = commons.concat (entries.map (t => `entry-${t}`));

tsts = tsts.concat (commons.map (t => `main-${t}`)).concat (commons.map (t => `init-${t}`));

await this.update ([ 'live/tst/loop.sh' ].concat (tsts.map (t => `live/tst/tst-${t}.out`)));

//await this.update ([ 'tst/tst-live-sig-hand-sig-action-ut.out' ]);
