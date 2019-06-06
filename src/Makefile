all:
	node ../make/make.js -j 4 . ../build/src $(if $a,$a,int/tst-basic.out common/dump-record replay/replay analysis/analysis)

strict-tst:
	bash live/tst/loop.sh node ../make/make.js -j 4 . ../build/src all -p tst/goal/out.g
