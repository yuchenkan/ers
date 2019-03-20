m4_changecom(`~~')m4_dnl
m4_define(`m4_upcase', `m4_translit(`$*', `a-z', `A-Z')')m4_dnl
m4_define(`m4_lowcase', `m4_translit(`$*', `A-Z', `a-z')')m4_dnl
m4_define(`m4_expand', $1)m4_dnl
m4_dnl
m4_define(`m4_ns', ``$2'm4_namespace`$1'')m4_dnl
