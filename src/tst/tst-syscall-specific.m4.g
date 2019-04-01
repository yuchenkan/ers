'use strict'; /* vim: set ft=javascript: */

const ext = env.trim (goal).split ('.').pop ();

//m4_define(\\\`m4_syscall', \\\`ERS_SYSCALL (\\$1)')m4_dnl
//m4_define(\\\`m4_syscall', \\\`ERS_SYSCALL (\\$1)m4_ifelse(\\$1, 0, \\\`; testq %rax, %rax; jnz 1f; ERI_ASSERT_FALSE; 1:')')m4_dnl

await env.run (`cat >${goal} <<EOF
m4_define(\\\`m4_namespace', \\\`tst_')m4_dnl
m4_define(\\\`m4_syscall', \\\`ERS_SYSCALL (\\$1)')m4_dnl
m4_define(\\\`m4_atomic_h', \\\`tst/tst-atomic.h')m4_dnl
m4_include(\\\`lib/syscall-impl.${ext}.m4')m4_dnl
EOF`);
