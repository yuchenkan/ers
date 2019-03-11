all:
	node ../make/make.js -j 4 . ../build/src $(if $A,$A,int/tst-basic.out dump-record)

live-strict-tst:
	bash live/tst/loop.sh node ../make/make.js -j 4 . ../build/src live/tst/all -p goal/tst/out.g
