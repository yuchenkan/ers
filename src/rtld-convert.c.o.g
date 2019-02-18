'use strict'; /* vim: set ft=javascript: */

await this.invoke ('goal/compile.g', { cflags: f => env.filter (f, /^-(O(\d|fast|g|s)|g|Wall|Werror)/) });
