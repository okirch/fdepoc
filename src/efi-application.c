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

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <iconv.h>
#include <limits.h>

#include <tss2/tss2_tpm2_types.h>

#include "eventlog.h"
#include "bufparser.h"
#include "runtime.h"
#include "util.h"


/*
 * Process EFI Boot Service Application events
 */

static void
__tpm_event_efi_bsa_destroy(tpm_parsed_event_t *parsed)
{
	__tpm_event_efi_device_path_destroy(&parsed->efi_bsa_event.device_path);
}

static void
__tpm_event_efi_bsa_print(tpm_parsed_event_t *parsed, tpm_event_bit_printer *print_fn)
{
#if 0
	print_fn("BSA image loc=%Lx", (unsigned long long) parsed->efi_bsa_event.image_location);
	print_fn(" len=%Lx", (unsigned long long) parsed->efi_bsa_event.image_length);
	print_fn(" lt-addr=%Lx", (unsigned long long) parsed->efi_bsa_event.image_lt_address);
	print_fn("\n");
#endif

	print_fn("Boot Service Application; device path:\n");
	__tpm_event_efi_device_path_print(&parsed->efi_bsa_event.device_path, print_fn);
}

bool
__tpm_event_parse_efi_bsa(tpm_event_t *ev, tpm_parsed_event_t *parsed, buffer_t *bp)
{
	size_t device_path_len;
	buffer_t path_buf;

	parsed->destroy = __tpm_event_efi_bsa_destroy;
	parsed->print = __tpm_event_efi_bsa_print;

	if (!buffer_get_u64le(bp, &parsed->efi_bsa_event.image_location)
	 || !buffer_get_size(bp, &parsed->efi_bsa_event.image_length)
	 || !buffer_get_size(bp, &parsed->efi_bsa_event.image_lt_address)
	 || !buffer_get_size(bp, &device_path_len)
	 || !buffer_get_buffer(bp, device_path_len, &path_buf))
		return false;

	if (!__tpm_event_parse_efi_device_path(&parsed->efi_bsa_event.device_path, &path_buf))
		return false;

	return true;
}

bool
tpm_efi_bsa_event_extract_location(tpm_parsed_event_t *parsed, char **dev_ret, char **path_ret)
{
	const struct efi_device_path *efi_path;
	const struct efi_device_path_item *item;
	unsigned int i;

	if (parsed->event_type != TPM2_EFI_BOOT_SERVICES_APPLICATION)
		return false;

	drop_string(path_ret);

	efi_path = &parsed->efi_bsa_event.device_path;
	for (i = 0, item = efi_path->entries; i < efi_path->count; ++i, ++item) {
		char pathbuf[PATH_MAX];
		const char *uuid, *filepath;

		if ((uuid = __tpm_event_efi_device_path_item_harddisk_uuid(item)) != NULL) {
			char *dev_path;

			snprintf(pathbuf, sizeof(pathbuf), "/dev/disk/by-partuuid/%s", uuid);
			if ((dev_path = realpath(pathbuf, NULL)) == NULL) {
				fprintf(stderr, "Error: cannot find device for partition with uuid %s\n", uuid);
				return false;
			}

			drop_string(dev_ret);
			*dev_ret = dev_path;
		}

		if ((filepath = __tpm_event_efi_device_path_item_file_path(item)) != NULL) {
			assign_string(path_ret, filepath);
		}
	}

	return *dev_ret && *path_ret;
}

