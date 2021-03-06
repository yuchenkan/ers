'use strict'; /* vim: set ft=javascript: */

return [ 'basic', 'clone', 'clear-tid', 'raise', 'sig-ignore', 'sig-nest', 'sig-exit-group',
  'sig-sig-mask', 'sigprocmask', 'sig-sig-prepare-sync', 'single-step', 'sync-async',
  'sigaltstack', 'sigpending', 'sigsuspend', 'sigtimedwait', 'signalfd', 'io', 'mmap', 'stat',
  'link', 'getdents', 'chmod', 'uname', 'atomic', 'rwlock', 'futex', 'clock', 'rlimit', 'socket',
  'chdir', 'cred', 'restart-futex', 'getrandom', 'nice', 'umask', 'chown', 'pipe',
  'restart-pipe', 'select', 'poll', 'epoll', 'mremap', 'udp', 'sysinfo' ].concat ([ ...Array (6).keys () ].map (x => `exit-${x}`));
