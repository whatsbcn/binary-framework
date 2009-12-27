all:	sk
sk:	include/magic.h elfuck/ef dietlibc/diet src/skv
	@(cd src; make skv)
	@dietlibc/bin/elftrunc src/skv skv.in
	elfuck/ef -lbs9 skv.in skv
	@ls -la skv
	@rm -f skv.in
elfuck/ef: dietlibc/diet
	@(cd elfuck; make)
dietlibc/diet:
	@(cd dietlibc; make)

src/skv: 
	cd src; make skv

include/magic.h:
	@echo "#ifndef MAGIC_H" > include/magic.h
	@echo "#define MAGIC_H" >> include/magic.h
	@echo "#define CONFMAGIC \"`od -A n --width=64 -N 64 -t x1 /dev/urandom | sed -e 's/ /\\\\x/g'`\"" >> include/magic.h
	@echo "#define CONFKEY \"`od -A n --width=64 -N 64 -t x1 /dev/urandom | sed -e 's/ /\\\\x/g'`\"" >> include/magic.h
	@echo "#endif" >> include/magic.h

clean:
	rm -f skv core .depend include/magic.h
	@(cd src; make clean)
	@(cd elfuck; make clean)
	@(cd dietlibc; make clean)
