

CFLAGS	= -Wall -I /usr/include/tss2
LINK	= -ltss2-fapi -lcrypto

all: pcr-oracle

install: pcr-oracle
	install -d $(DESTDIR)/bin
	install -m 755 pcr-oracle $(DESTDIR)/bin

clean:
	rm -f pcr-oracle *.o

pcr-oracle: oracle.o
	$(CC) -o $@ $< $(LINK)

dist:
	mkdir -p pcr-oracle-0.1
	cp Makefile *.c pcr-oracle-0.1
	tar cvjf pcr-oracle-0.1.tar.bz2 pcr-oracle-0.1/*
	rm -rf pcr-oracle-0.1
