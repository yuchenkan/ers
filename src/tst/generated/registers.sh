set -ex

echo '#ifndef TST_GENERATED_REGISTER_H'
echo '#define TST_GENERATED_REGISTER_H'
echo

gregs="rax rbx rcx rdx rdi rsi rsp rbp r8 r9 r10 r11 r12 r13 r14 r15"

up () { echo $1 | awk '{print toupper($0)}'; }

echo -n '#define TST_FOREACH_GENERAL_REG(p, ...)'
for r in $gregs; do
  echo ' \'
  echo -n '  p ('$(up $r)', '$r', ##__VA_ARGS__)'
done
echo

echo

echo -n '#define TST_FOREACH_GENERAL_REG2(p, ...)'
for r in $gregs; do
  for s in $gregs; do
  echo ' \'
  echo -n '  p ('$(up $r)', '$r', '$(up $s)', '$s', ##__VA_ARGS__)'
  done
done

echo
echo '#endif'
