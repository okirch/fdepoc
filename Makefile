PKGNAME		= fde-tools-0.4

CCOPT		= -O0 -g
SYSCONFIGDIR	= /etc/sysconfig
FDE_SHARE_DIR	= /usr/share/fde
FIRSTBOOTDIR	= /usr/share/jeos-firstboot
CFLAGS		= -Wall $(CCOPT)
FIDO_LINK	= -lfido2 -lcrypto
TOOLS		= fde-token

LIBSCRIPTS	= util
_LIBSCRIPTS	= $(addprefix share/,$(LIBSCRIPTS))

all: $(TOOLS)

install:: $(TOOLS)
	install -d $(DESTDIR)/bin
	install -m 755 $(TOOLS) $(DESTDIR)/bin

install::
	@mkdir -p $(DESTDIR)$(FIRSTBOOTDIR)/modules
	@cp -v firstboot/fde $(DESTDIR)$(FIRSTBOOTDIR)/modules/fde
	@mkdir -p $(DESTDIR)$(SYSCONFIGDIR)
	@cp -v sysconfig.fde $(DESTDIR)$(SYSCONFIGDIR)/fde
	@mkdir -p $(DESTDIR)$(FDE_SHARE_DIR)
	@cp -v $(_LIBSCRIPTS) $(DESTDIR)$(FDE_SHARE_DIR)

clean:
	rm -f $(TOOLS)
	rm -rf build

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
