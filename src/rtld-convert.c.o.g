'use strict'; /* vim: set ft=javascript: */

const script = 'goals/compile.g';

await this.update ([ script ], async () => {
  await this.invoke (script, { cflags: f => env.filter (f, /^-(O(\d|fast|g|s)|g|Wall|Werror)/) });
});
