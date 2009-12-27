
all: src/mig-logcleaner.c
	cd src; make all
	dietlibc/bin/elftrunc src/mig-logcleaner lc.in
	elfuck/ef -lbs9 lc.in lc
	rm lc.in

elfuck/ef:
	cd elfuck; make

clean:
	rm -f lc
	cd src; make clean
	#cd elfuck; make clean
