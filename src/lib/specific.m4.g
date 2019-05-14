'use strict'; /* vim: set ft=javascript: */

if (typeof ns === 'undefined') var ns = 'eri_';
if (typeof header === 'undefined') var header = x => `lib/${x}-specific.h`;

const ext = env.ext (env.trim (goal));

const name = goal.match (/.*\b[-\/]([a-z]*)-specific\.[^.]*.m4$/)[1];
if (name === 'lock')
  var headers = [ 'lock', 'syscall', 'atomic' ];
else
  var headers = [ 'lock', 'printf', 'syscall' ];
const head = headers.map (x => `m4_define(\\\`m4_${x}_h', \\\`${header (x)}')m4_dnl`).join ('\n');

await env.run (`cat >${goal} <<EOF
m4_define(\\\`m4_namespace', \\\`${ns}')m4_dnl
${head}
m4_include(\\\`lib/${name}-impl.${ext}.m4')m4_dnl
EOF`);
