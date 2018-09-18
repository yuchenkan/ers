all:
	# bash make.sh
	gcc -lpthread tracee.c -o tracee
	gcc -g -I .. -O3 ../common.c ../lib/util.c ../lib/printf.c tracer.c -o tracer
