set -ex

gcc -I . -g -fPIC -Wl,-e,tst_start -nostdlib -shared -o tst-rtld-recorder.so tst/tst-rtld-recorder.c tst/tst-rtld-recorder.S lib/printf.c lib/lock.c lib/util.c lib/buf.c -Wl,--no-undefined -Wall -fvisibility=hidden -O3 -fno-tree-loop-distribute-patterns

gcc -I . rtld-convert.c -o rtld-convert

./rtld-convert recorder tst-rtld-recorder.so tst-rtld-recorder tst-rtld-recorder-binary.h

gcc -I . -g -fPIE -Wl,-Map,rtld.map -Wl,-T,rtld.ld -Wl,-e,eri_start -o rtld rtld.c rtld.S lib/util.c lib/printf.c -fvisibility=hidden -nostdlib -pie -D ERI_TST_RTLD -fdata-sections -ffunction-sections -Wl,--gc-sections -Wl,-N -Wall -Wl,--no-undefined -O3 -fno-tree-loop-distribute-patterns

#gcc -I . -g -fPIE -Wl,-Map,rtld.map -Wl,-T,rtld.ld -Wl,-e,start -o rtld rtld.c -fvisibility=hidden -nostdlib -pie -Wl,-N
#objcopy -R .eh_frame -R .eh_frame_hdr -R .note.gnu.build-id -R .dynsym -R .dynstr -R .gnu.hash rtld
#objcopy -R .eh_frame -R .eh_frame_hdr -R .note.gnu.build-id -R .dynsym -R .dynstr -R .gnu.hash -R .rela.dyn -R .dynamic -R .got -R .got.plt rtld
#objcopy -R .eh_frame -R .eh_frame_hdr -R .note.gnu.build-id rtld
objcopy -R .eh_frame -R .eh_frame_hdr -R .note.gnu.build-id -R .dynsym -R .dynstr -R .gnu.hash -R .rela.dyn -R .dynamic -R .got -R .got.plt rtld

./rtld-convert rtld rtld public/tst-rtld.h

gcc -I . tst/tst-rtld.S -o tst-rtld -nostdlib -fPIE -pie -Wall -Wl,-e,start -g -D ERI_TST_RTLD -O3 -fno-tree-loop-distribute-patterns
