
all:
	cd src; make

config: include/config.h

include/config.h: src/config.c
	cd src; make ../include/config.h

clean:
	cd src; make cleanall
