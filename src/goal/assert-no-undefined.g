'use strict'; /* vim: set ft=javascript: */

await env.run (`(($(nm -u ${goal} | grep -v _GLOBAL_OFFSET_TABLE_ | awk '{ print; print >"/dev/stderr" }' | wc -l) == 0))`);
