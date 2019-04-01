'use strict'; /* vim: set ft=javascript: */

const ext = env.trim (goal).split ('.').pop ();
await env.run (`cat >${goal} <<EOF
m4_define(\\\`m4_namespace', \\\`eri_')m4_dnl
m4_define(\\\`m4_syscall', \\\`syscall')m4_dnl
m4_define(\\\`m4_syscall_h', \\\`lib/syscall-specific.h')m4_dnl
m4_define(\\\`m4_atomic_h', \\\`lib/atomic-specific.h')m4_dnl
m4_include(\\\`lib/syscall-impl.${ext}.m4')m4_dnl
EOF`);
