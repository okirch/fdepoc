MANDIR := $(DESTDIR)/usr/share/man
vpath %.sh ../

all: fdectl.8

fdectl.8: fdectl.h2m fde.sh
	help2man --no-info --section=8 -i $< -o $@ $(shell echo $^ | awk '{print $$2}')

install: all
	@install -d $(MANDIR)/man8
	@install -m 644 fdectl.8 $(MANDIR)/man8
