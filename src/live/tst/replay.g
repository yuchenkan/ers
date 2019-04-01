'use strict'; /* vim: set ft=javascript: */

/* XXX: decouple with replay... */
return [ 'basic', 'clone', 'raise', 'sigprocmask', 'sigtimedwait' ].concat ([ ...Array (6).keys () ].map (x => `exit-${x}`));
