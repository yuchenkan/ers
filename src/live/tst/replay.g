'use strict'; /* vim: set ft=javascript: */

/* XXX: decouple with replay... */
return [ 'basic', 'clone', 'sigprocmask', 'sigtimedwait' ].concat ([ ...Array (6).keys () ].map (x => `exit-${x}`));
