

CFLAGS	= -Wall -I /usr/include/tss2
LINK	= -ltss2-fapi -lcrypto

all: oracle

clean:
	rm -f thing *.o

thing: read_pcr.o
	$(CC) -o $@ $< $(LINK)

oracle: oracle.o
	$(CC) -o $@ $< $(LINK)
