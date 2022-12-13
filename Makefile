PKGNAME		= fde-tools-0.6.1

CCOPT		= -O0 -g
SBINDIR		= /sbin
SYSCONFIGDIR	= /etc/sysconfig
FDE_SHARE_DIR	= /usr/share/fde
FIRSTBOOTDIR	= /usr/share/jeos-firstboot
CFLAGS		= -Wall $(CCOPT)
FIDO_LINK	= -lfido2 -lcrypto
TOOLS		= fde-token

LIBSCRIPTS	= grub2 \
		  luks \
		  tpm \
		  uefi \
		  util \
		  ui/dialog \
		  ui/shell \
		  commands/passwd \
		  commands/add-secondary-key \
		  commands/tpm-enable \
		  commands/tpm-present

_LIBSCRIPTS	= $(addprefix share/,$(LIBSCRIPTS))

all: $(TOOLS)

install:: $(TOOLS)
	install -d $(DESTDIR)/bin
	install -m 755 $(TOOLS) $(DESTDIR)/bin

install::
	@mkdir -p $(DESTDIR)$(FIRSTBOOTDIR)/modules
	@cp -v firstboot/fde $(DESTDIR)$(FIRSTBOOTDIR)/modules/fde
	@mkdir -p $(DESTDIR)$(SYSCONFIGDIR)
	@cp -v sysconfig.fde $(DESTDIR)$(SYSCONFIGDIR)/fde-tools
	@mkdir -p $(DESTDIR)$(FDE_SHARE_DIR)
	@for name in $(LIBSCRIPTS); do \
		d=$$(dirname $$name); \
		mkdir -p $(DESTDIR)$(FDE_SHARE_DIR)/$$d; \
		cp -v share/$$name $(DESTDIR)$(FDE_SHARE_DIR)/$$d; \
	done
	@mkdir -p $(DESTDIR)$(SBINDIR)
	@install -m 555 -v fde.sh $(DESTDIR)$(SBINDIR)/fdectl

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
	cp -a Makefile sysconfig.fde fde.sh src share firstboot $(PKGNAME)
	@find $(PKGNAME) -name '.*.swp' -o -name '*.{rej,orig}' -exec rm {} \;
	tar -cvjf $(PKGNAME).tar.bz2 $(PKGNAME)/*
	rm -rf $(PKGNAME)
