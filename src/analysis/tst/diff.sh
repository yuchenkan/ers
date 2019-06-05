set -e

l1=$(ls -1 $1 | grep l)
l2=$(ls -1 $2 | grep l)

[ "$l1" == "$l2" ]

>$3

for f in $l1; do
  echo $f >>$3
  diff $1/$f $2/$f >>$3
done
