'use strict'; /* vim: set ft=javascript: */

const live = `${env.trim (env.trim (goal)).replace ('tst-', '')}.l`;
await env.run (`cat >${goal} <<EOF
m4_define(\\\`m4_live', \\\`${live}')m4_dnl
m4_include(\\\`tst/tst-live-impl.ld.m4')m4_dnl
EOF`);
