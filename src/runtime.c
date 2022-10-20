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

static buffer_t *
__system_read_file(const char *filename, int flags)
{
	buffer_t *bp;
	struct stat stb;
	off_t size;
	int count;
	int fd;

	debug("Reading %s\n", filename);
	if ((fd = open(filename, O_RDONLY)) < 0)
		fatal("Unable to open file %s: %m\n", filename);

	if (fstat(fd, &stb) < 0)
		fatal("Cannot stat %s: %m\n", filename);

	if (flags & RUNTIME_READ_EFIVARFS) {
		/* The first 4 bytes (uint32_t) of the efivarfs file represent
		 * the attributes of the variable. Skip them.
		 */
		if (lseek(fd, 4, SEEK_SET) < 0)
			fatal("Cannot seek %s: %m\n", filename);
		size = stb.st_size - 4;
	} else {
		size = stb.st_size;
	}

	bp = buffer_alloc_write(size);
	if (bp == NULL)
		fatal("Cannot allocate buffer of %lu bytes for %s: %m\n",
				(unsigned long) size,
				filename);

	count = read(fd, bp->data, size);
	if (count < 0)
		fatal("Error while reading from %s: %m\n", filename);

	if (flags & RUNTIME_SHORT_READ_OKAY) {
		/* NOP */
	} else if (count != size) {
		fatal("Short read from %s\n", filename);
	}

	close(fd);

	debug("Read %u bytes from %s\n", count, filename);
	bp->wpos = count;
	return bp;
}

static buffer_t *
__system_read_efi_variable(const char *var_name)
{
	char filename[PATH_MAX];

	/* Read the variable from efivar sysfs */
	snprintf(filename, sizeof(filename), "/sys/firmware/efi/vars/%s/data", var_name);
	if (access(filename, F_OK) == 0)
		return __system_read_file(filename, RUNTIME_SHORT_READ_OKAY);

	/* Read the variable in efivarfs sysfs */
	snprintf(filename, sizeof(filename), "/sys/firmware/efi/efivars/%s", var_name);
	return __system_read_file(filename, RUNTIME_SHORT_READ_OKAY | RUNTIME_READ_EFIVARFS);
}

buffer_t *
runtime_read_file(const char *path, int flags)
{
	return __system_read_file(path, flags);
}

buffer_t *
runtime_read_efi_variable(const char *var_name)
{
	return __system_read_efi_variable(var_name);
}

