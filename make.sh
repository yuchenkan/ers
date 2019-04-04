set -ex

cflags=$(node -e "console.log ((() => { $(cat basic-cflags.g) }) ())")

(cd 3rd/xed && ./mfile.py --extra-flags="-g $cflags")

(cd src && make a=all)

(cd doc && make -j 4)
