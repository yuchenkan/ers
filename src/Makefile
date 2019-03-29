all:
	node ../make/make.js -j 4 . ../build/src $(if $a,$a,int/tst-basic.out dump-record replay/replay)

live-strict-tst:
	bash live/tst/loop.sh node ../make/make.js -j 4 . ../build/src live/tst/all -p goal/tst/out.g
