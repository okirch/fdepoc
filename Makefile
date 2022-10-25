PKGNAME		= fde-tools-0.3

CCOPT		= -O0 -g
FIRSTBOOTDIR	= /usr/share/jeos-firstboot
CFLAGS		= -Wall -I /usr/include/tss2 $(CCOPT)
FAPI_LINK	= -ltss2-fapi -lcrypto
FIDO_LINK	= -lfido2 -lcrypto
TOOLS		= pcr-oracle fde-token

ORACLE_SRCS	= oracle.c \
		  eventlog.c \
		  efi-devpath.c \
		  efi-variable.c \
		  efi-application.c \
		  efi-gpt.c \
		  digest.c \
		  runtime.c \
		  authenticode.c \
		  util.c
ORACLE_OBJS	= $(addprefix build/,$(patsubst %.c,%.o,$(ORACLE_SRCS)))

all: $(TOOLS)

install:: $(TOOLS)
	install -d $(DESTDIR)/bin
	install -m 755 $(TOOLS) $(DESTDIR)/bin

install::
	@mkdir -p $(DESTDIR)$(FIRSTBOOTDIR)/modules
	@cp -v firstboot/fde $(DESTDIR)$(FIRSTBOOTDIR)/modules/fde

clean:
	rm -f $(TOOLS)
	rm -rf build

pcr-oracle: $(ORACLE_OBJS)
	$(CC) -o $@ $(ORACLE_OBJS) $(FAPI_LINK)

fde-token: build/fde-token.o
	$(CC) -o $@ $< $(FIDO_LINK)

build/%.o: src/%.c
	@mkdir -p build
	$(CC) -o $@ $(CFLAGS) -c $<

dist:
	mkdir -p $(PKGNAME)
	cp -a Makefile src firstboot $(PKGNAME)
	tar cvjf $(PKGNAME).tar.bz2 $(PKGNAME)/*
	rm -rf $(PKGNAME)
