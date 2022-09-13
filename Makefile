PKGNAME		= fde-tools-0.2

CCOPT		= -O0 -g
FIRSTBOOTDIR	= /usr/share/jeos-firstboot
DRACUTDIR	= /usr/lib/dracut
DRACUTMODDIR	= /usr/lib/dracut/modules.d
CFLAGS		= -Wall -I /usr/include/tss2 $(CCOPT)
FAPI_LINK	= -ltss2-fapi -lcrypto
FIDO_LINK	= -lfido2 -lcrypto
TOOLS		= pcr-oracle fde-token

ORACLE_SRCS	= oracle.c eventlog.c efi-devpath.c digest.c util.c
ORACLE_OBJS	= $(addprefix build/,$(patsubst %.c,%.o,$(ORACLE_SRCS)))

all: $(TOOLS)

install:: $(TOOLS)
	install -d $(DESTDIR)/bin
	install -m 755 $(TOOLS) $(DESTDIR)/bin

install::
	@mkdir -p $(DESTDIR)$(FIRSTBOOTDIR)/modules
	@cp -v firstboot/fde $(DESTDIR)$(FIRSTBOOTDIR)/modules/fde

install::
	@mkdir -p $(DESTDIR)$(DRACUTMODDIR)
	@for module in `ls dracut`; do \
		mkdir -p $(DESTDIR)$(DRACUTMODDIR)/$$module; \
		cp -av dracut/$$module/* $(DESTDIR)$(DRACUTMODDIR)/$$module/; \
	done

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
	cp -a Makefile src firstboot dracut $(PKGNAME)
	tar cvjf $(PKGNAME).tar.bz2 $(PKGNAME)/*
	rm -rf $(PKGNAME)
