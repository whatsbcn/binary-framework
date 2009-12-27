CC = dietlibc/bin/diet gcc
LD = ld 
EXTRA_CFLAGS = 
CFLAGS=-Wall -fno-builtin -O2 -fomit-frame-pointer -nostdinc -DNODIETREF -I./dietlibc/include $(EXTRA_CFLAGS) 
LDFLAGS = -s

all: mig-logcleaner.c
	$(CC) $(CFLAGS) $(LDFLAGS) -Wall -o mig-logcleaner mig-logcleaner.c

clean:
	rm -f mig-logcleaner *~

