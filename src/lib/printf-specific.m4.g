'use strict'; /* vim: set ft=javascript: */

const ext = env.ext (env.trim (goal));
await env.run (`cat >${goal} <<EOF
m4_define(\\\`m4_namespace', \\\`${ns}')m4_dnl
m4_define(\\\`m4_lock_h', \\\`${header ('lock')}')m4_dnl
m4_define(\\\`m4_printf_h', \\\`${header ('printf')}')m4_dnl
m4_define(\\\`m4_syscall_h', \\\`${header ('syscall')}')m4_dnl
m4_include(\\\`lib/printf-impl.${ext}.m4')m4_dnl
EOF`);
