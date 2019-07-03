set -ex

cd $(dirname "$0")

trd_xed=3rd/xed
if [ ! -d $trd_xed ]; then
  mkdir -p $trd_xed
  git clone https://github.com/intelxed/xed.git $trd_xed
fi

trd_xed_mbuild=$trd_xed/../mbuild
if [ ! -d $trd_xed_mbuild ]; then
  mkdir -p $trd_xed_mbuild
  git clone https://github.com/intelxed/mbuild.git $trd_xed_mbuild
fi

cflags=$(node -e "console.log ((() => { $(cat basic-cflags.g) }) ())")

(cd $trd_xed && ./mfile.py --extra-flags="-g $cflags")

src_xed=src/analysis/xed.gen
rm -rf $src_xed
mkdir $src_xed

trd_xed_pub=$trd_xed/include/public/xed
trd_xed_obj=$trd_xed/obj

trd_xed_pub_src=$(realpath --relative-to=$src_xed $trd_xed_pub)
trd_xed_obj_src=$(realpath --relative-to=$src_xed $trd_xed_obj)

ls -1 $trd_xed_pub/ | xargs -I {} ln -sf $trd_xed_pub_src/{} $src_xed/
ls -1 $trd_xed_obj/ | grep \\.h | xargs -I {} ln -sf $trd_xed_obj_src/{} $src_xed/
ln -s $trd_xed_obj_src/libxed.a $src_xed/

(cd src && make a=all)

(cd doc && make -j 4)
