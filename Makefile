CC	= clang
CFLAGS	= -Wall 

.PHONY:	all
all:	bytelocker

bytelocker:		bytelocker.c bytelocker.h main.c
	$(CC) $(CFLAGS) main.c bytelocker.c -o bytelocker

.PHONY: clean
clean:
	-rm -f bytelocker
