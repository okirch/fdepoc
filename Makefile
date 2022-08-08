
CCOPT		= -O0 -g
CFLAGS		= -Wall -I /usr/include/tss2 $(CCOPT)
FAPI_LINK	= -ltss2-fapi -lcrypto
FIDO_LINK	= -lfido2 -lcrypto

all: pcr-oracle fde-token

install: pcr-oracle
	install -d $(DESTDIR)/bin
	install -m 755 pcr-oracle $(DESTDIR)/bin

clean:
	rm -f pcr-oracle *.o

pcr-oracle: oracle.o
	$(CC) -o $@ $< $(FAPI_LINK)

fde-token: fde-token.o
	$(CC) -o $@ $< $(FIDO_LINK)

dist:
	mkdir -p pcr-oracle-0.1
	cp Makefile *.c pcr-oracle-0.1
	tar cvjf pcr-oracle-0.1.tar.bz2 pcr-oracle-0.1/*
	rm -rf pcr-oracle-0.1
