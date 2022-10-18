/*
 *   Copyright (C) 2022 SUSE LLC
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include "runtime.h"

static bufbuilder_t *
__system_read_file(const char *filename, int flags)
{
	bufbuilder_t *bp;
	struct stat stb;
	int count;
	int fd;

	debug("Reading %s\n", filename);
	if ((fd = open(filename, O_RDONLY)) < 0)
		fatal("Unable to open file %s: %m\n", filename);

	if (fstat(fd, &stb) < 0)
		fatal("Cannot stat %s: %m\n", filename);

	bp = bufbuilder_alloc(stb.st_size);
	if (bp == NULL)
		fatal("Cannot allocate buffer of %lu bytes for %s: %m\n",
				(unsigned long) stb.st_size,
				filename);

	count = read(fd, bp->data, stb.st_size);
	if (count < 0)
		fatal("Error while reading from %s: %m\n", filename);

	if (flags & RUNTIME_SHORT_READ_OKAY) {
		/* NOP */
	} else if (count != stb.st_size) {
		fatal("Short read from %s\n", filename);
	}

	close(fd);

	debug("Read %u bytes from %s\n", count, filename);
	return bp;
}

static bufbuilder_t *
__system_read_efi_variable(const char *var_name)
{
	char filename[PATH_MAX];

	snprintf(filename, sizeof(filename), "/sys/firmware/efi/vars/%s/data", var_name);
	return __system_read_file(filename, RUNTIME_SHORT_READ_OKAY);
}

bufbuilder_t *
runtime_read_file(const char *path, int flags)
{
	return __system_read_file(path, flags);
}

bufbuilder_t *
runtime_read_efi_variable(const char *var_name)
{
	return __system_read_efi_variable(var_name);
}

