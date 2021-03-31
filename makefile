CFLAGS = -I. -lcrypto -lssl
CC = gcc

test: test.c certChecker.c certChecker.h makefile
	$(CC) -g -Wall -o test test.c certChecker.c $(CFLAGS)

clean :
	rm test