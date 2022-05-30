

CFLAGS	= -Wall -I /usr/include/tss2
LINK	= -ltss2-fapi

all: thing

clean:
	rm -f thing *.o

thing: read_pcr.o
	$(CC) -o $@ $< $(LINK)
