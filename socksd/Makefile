DIET  =   ./dietlibc/bin/diet gcc
GCC   =   gcc
CFLAGS = -Wall -fno-builtin -O2 -I../include -fomit-frame-pointer -nostdinc -DNODIETREF -I../../dietlibc/include $(EXTRA_CFLAGS)
LDFLAGS = -s

all: socksd.nptl socksd.diet

dietlibc: ../dietlibc/bin/diet

../dietlibc/bin/diet:
	cd ../dietlibc; make
	cd ../dietlibc; ln -s bin-* bin
	ln -fs ../dietlibc/ .

socksd.diet: socksd.c dietlibc
	$(DIET) $(CFLAGS) $(LDFLAGS) socksd.c -o socksd.in -lpthread
	../elfuck/ef -lbs9 socksd.in socksd.diet
	rm -f socksd.in

socksd.nptl: socksd.c
	$(GCC) socksd.c -o socksd.nptl -lpthread -DDIETLIBC

clean:
	rm -f socksd.diet socksd.nptl socksd.in
