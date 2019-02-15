'use strict'; /* vim: set ft=javascript: */

const script = 'goals/link.g';
const srcs = [ `${goal}.l` ];
const ldflags = f => `${f} -pie -Wl,-Map,${goal}.map -Wl,-T,rtld.ld -Wl,-e,eri_start -Wl,--gc-sections -Wl,-N`;

await this.update ([ script, 'rtld.ld' ].concat (srcs), async () => {
  await this.invoke (script, { srcs, ldflags });
  await env.run (`objcopy -R .eh_frame -R .eh_frame_hdr -R .note.gnu.build-id -R .dynsym `
		+ `-R .dynstr -R .gnu.hash -R .rela.dyn -R .dynamic -R .got -R .got.plt ${goal}`);
});
