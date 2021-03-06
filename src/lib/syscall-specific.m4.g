'use strict'; /* vim: set ft=javascript: */

if (typeof ns === 'undefined') var ns = 'eri_';
if (typeof syscall === 'undefined') var syscall = 'syscall';
if (typeof header === 'undefined') var header = x => `lib/${x}-specific.h`;

const ext = env.ext (env.trim (goal));
await env.run (`cat >${goal} <<EOF
m4_define(\\\`m4_namespace', \\\`${ns}')m4_dnl
m4_define(\\\`m4_syscall', \\\`${syscall}')m4_dnl
m4_define(\\\`m4_syscall_h', \\\`${header ('syscall')}')m4_dnl
m4_define(\\\`m4_atomic_h', \\\`${header ('atomic')}')m4_dnl
m4_include(\\\`lib/syscall-impl.${ext}.m4')m4_dnl
EOF`);
