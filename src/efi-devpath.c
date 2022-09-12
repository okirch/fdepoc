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

#if 0
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <iconv.h>
#include <limits.h>
#endif

#include <string.h>

#include <tss2/tss2_tpm2_types.h>

#include "eventlog.h"
#include "bufparser.h"
#include "util.h"

extern const char *	tpm_event_decode_uuid(const unsigned char *data);

bool
__tpm_event_parse_efi_device_path(efi_device_path_t *path, bufparser_t *bp)
{
	while (!bufparser_eof(bp)) {
		struct efi_device_path_item *item;

		if (path->count >= EFI_DEVICE_PATH_MAX)
			fatal("Cannot parse EFI device path - too many entries");
		item = &path->entries[path->count++];

		if (!bufparser_get_u8(bp, &item->type)
		 || !bufparser_get_u8(bp, &item->subtype)
		 || !bufparser_get_u16le(bp, &item->len))
			return false;

		/* encoded len includes the size of the header */
		item->len -= 4;

		item->data = malloc(item->len);
		if (!bufparser_get(bp, item->data, item->len))
			return false;
	}

	return true;
}

/*
 * Handle EFI device path information in a rudimentary fashion.
 * Enought to locate the mentioned files in the file system.
 */
static const char *
__efi_device_path_type_to_string(unsigned int type, unsigned int subtype)
{
	static char retbuf[128];
	const char *type_string;

	switch (type) {
	case TPM2_EFI_DEVPATH_TYPE_HARDWARE_DEVICE:
		type_string = "hardware"; break;
	case TPM2_EFI_DEVPATH_TYPE_ACPI_DEVICE:
		if (subtype == TPM2_EFI_DEVPATH_ACPI_SUBTYPE_ACPI)
			return "ACPI";

		type_string = "acpi"; break;
	case TPM2_EFI_DEVPATH_TYPE_MESSAGING_DEVICE:
		if (subtype == TPM2_EFI_DEVPATH_MESSAGING_SUBTYPE_SATA)
			return "SATA";

		type_string = "messaging"; break;
	case TPM2_EFI_DEVPATH_TYPE_MEDIA_DEVICE:
		switch (subtype) {
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_HARDDRIVE:
			return "harddrive";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_CDROM:
			return "cdrom";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_VENDOR:
			return "vendor";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_FILE_PATH:
			return "file-path";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_MEDIA_PROTOCOL:
			return "media-protocol";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_PIWG_FIRMWARE:
			return "piwg-firmware";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_PIWG_FIRMWARE_VOLUME :
			return "piwg-firmware-volume";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_RELATIVE_OFFSET_RANGE :
			return "relative-offset-range";
		case TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_RAMDISK:
			return "ramdisk";
		}
		type_string = "hardware";
		break;
	case TPM2_EFI_DEVPATH_TYPE_BIOS_BOOT_DEVICE:
		type_string = "BIOS bootdev"; break;
	case TPM2_EFI_DEVPATH_TYPE_END:
		return "end";
	default:
		snprintf(retbuf, sizeof(retbuf), "type%u/subtype%u", type, subtype);
		return retbuf;
	}

	snprintf(retbuf, sizeof(retbuf), "%s/subtype%u", type_string, subtype);
	return retbuf;
}

const char *
__tpm_event_efi_device_path_item_harddisk_uuid(const struct efi_device_path_item *item)
{
	if (item->type == TPM2_EFI_DEVPATH_TYPE_MEDIA_DEVICE
	 && item->subtype == TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_HARDDRIVE)
		return tpm_event_decode_uuid(item->data + 20);

	return NULL;
}

const char *
__tpm_event_efi_device_path_item_file_path(const struct efi_device_path_item *item)
{
	static char file_path[PATH_MAX];

	if (item->type == TPM2_EFI_DEVPATH_TYPE_MEDIA_DEVICE
	 && item->subtype == TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_FILE_PATH) {
		bufparser_t file_path_buf;
		char *s;

		if (item->len / 2 >= sizeof(file_path))
			return NULL;

		bufparser_init(&file_path_buf, item->data, item->len);
		s = bufparser_get_utf16le(&file_path_buf, item->len / 2);
		if (s == NULL)
			return NULL;

		strncpy(file_path, s, sizeof(file_path) - 1);
		free(s);

		for (s = file_path; *s; ++s) {
			if (*s == '\\')
				*s = '/';
		}

		return file_path;
	}

	return NULL;
}

static void
__tpm_event_efi_device_path_item_print(const struct efi_device_path_item *item)
{
	const char *string;

	if (item->type == TPM2_EFI_DEVPATH_TYPE_END) {
		printf("  end\n");
		return;
	}

	if ((string = __tpm_event_efi_device_path_item_harddisk_uuid(item)) != NULL) {
		printf("  harddisk   part-uuid=%s\n", string);
		return;
	}

	if ((string = __tpm_event_efi_device_path_item_file_path(item)) != NULL) {
		printf("  file-path  \"%s\"\n", string);
		return;
	}

	if (item->type == TPM2_EFI_DEVPATH_TYPE_HARDWARE_DEVICE) {
		if (item->subtype == TPM2_EFI_DEVPATH_HARDWARE_SUBTYPE_PCI) {
			unsigned char pci_dev, pci_fn;

			pci_dev = ((unsigned char *) item->data)[1];
			pci_fn = ((unsigned char *) item->data)[0];
			printf("  PCI        %02x.%d\n", pci_dev, pci_fn);
			return;
		}
	}

	/* hard drive seems to have the UUID at offset 20 in item->data */

	printf("  %-10s len=%d data=",
			__efi_device_path_type_to_string(item->type, item->subtype),
			item->len);

	{
		unsigned char *data = item->data;
		unsigned int i;

		for (i = 0; i < item->len; ++i) {
			if (i)
				printf(":");
			printf("%02x", data[i]);
		}
	}

	printf("\n");
}

void
__tpm_event_efi_device_path_print(const efi_device_path_t *path)
{
	const struct efi_device_path_item *item;
	unsigned int i;

	for (i = 0, item = path->entries; i < path->count; ++i, ++item) {
		__tpm_event_efi_device_path_item_print(item);
	}
}

void
__tpm_event_efi_device_path_destroy(efi_device_path_t *path)
{
	unsigned int i;

	for (i = 0; i < path->count; ++i) {
		struct efi_device_path_item *item = &path->entries[i];

		free(item->data);
	}
	memset(path, 0, sizeof(*path));
}

