all:
	node ../make/make.js -j 4 . ../build/src $(if $a,$a,int/tst-basic.out common/dump-record replay/replay)

strict-tst:
	bash live/tst/loop.sh node ../make/make.js -j 4 . ../build/src live/tst/all replay/tst/all -p goal/tst/out.g
