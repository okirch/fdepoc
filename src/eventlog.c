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

#include "eventlog.h"
#include "util.h"

enum {
	__TPM2_ALG_SHA1 = 4,
	__TPM2_ALG_SHA256 = 11,
	__TPM2_ALG_SHA384 = 12,
	__TPM2_ALG_SHA512 = 13,

	TPM2_ALG_MAX
};

struct tpm_event_log_reader {
	int			fd;
	unsigned int		tpm_version;

	struct tpm_event_log_tcg2_info {
		uint32_t		platform_class;
		uint8_t			spec_version_major;
		uint8_t			spec_version_minor;
		uint8_t			spec_errata;
		uint8_t			uintn_size;

		tpm_algo_info_t		algorithms[TPM2_ALG_MAX];
	} tcg2_info;
};


static bool		__tpm_event_parse_tcg2_info(tpm_event_t *ev, struct tpm_event_log_tcg2_info *info);


static void
__read_exactly(int fd, void *vp, unsigned int len)
{
	int n;

	if ((n = read(fd, vp, len)) < 0)
		fatal("unable to read from event log: %m\n");
	if (n != len)
		fatal("short read from event log (premature EOF)\n");
}

static void
__read_u32le(int fd, uint32_t *vp)
{
	__read_exactly(fd, vp, sizeof(*vp));
	*vp = le32toh(*vp);
}

static void
__read_u16le(int fd, uint16_t *vp)
{
	__read_exactly(fd, vp, sizeof(*vp));
	*vp = le16toh(*vp);
}

static bool
__read_u32le_or_eof(int fd, uint32_t *vp)
{
	int n;

	if ((n = read(fd, vp, 4)) < 0)
		fatal("unable to read from event log: %m\n");
	if (n == 0)
		return false;

	if (n != 4)
		fatal("short read from event log (premature EOF)\n");
	*vp = le32toh(*vp);
	return true;
}

static const tpm_algo_info_t *
__get_algo_info(unsigned int algo_id, const tpm_algo_info_t *algorithms, unsigned int num_algoritms)
{
	const tpm_algo_info_t *algo;

	if (algo_id >= num_algoritms)
		return NULL;

	algo = &algorithms[algo_id];
	if (algo->digest_size == 0)
		return NULL;

	return algo;
}

static tpm_algo_info_t		tpm_algorithms[TPM2_ALG_MAX] = {
	[__TPM2_ALG_SHA1]	= {	"sha1",			20	},
	[__TPM2_ALG_SHA256]	= {	"sha256",		32	},
	[__TPM2_ALG_SHA384]	= {	"sha284",		48	},
	[__TPM2_ALG_SHA512]	= {	"sha512",		64	},
};

static const tpm_algo_info_t *
event_well_known_algo_info(unsigned int algo_id)
{
	return __get_algo_info(algo_id, tpm_algorithms, TPM2_ALG_MAX);
}

static const tpm_algo_info_t *
event_log_get_algo_info(tpm_event_log_reader_t *log, unsigned int algo_id)
{
	const tpm_algo_info_t *algo;

	algo = __get_algo_info(algo_id, log->tcg2_info.algorithms, TPM2_ALG_MAX);
	if (algo == NULL)
		algo = event_well_known_algo_info(algo_id);
	return algo;
}

static int
event_log_get_named_algo(const char *name)
{
	const tpm_algo_info_t *algo;
	int i;

	for (i = 0, algo = tpm_algorithms; i < TPM2_ALG_MAX; ++i, ++algo) {
		if (algo->openssl_name && !strcasecmp(algo->openssl_name, name))
			return i;
	}

	return -1;
}

tpm_event_log_reader_t *
event_log_open(void)
{
	const char *eventlog_path = "/sys/kernel/security/tpm0/binary_bios_measurements";
	tpm_event_log_reader_t *log;

	log = calloc(1, sizeof(*log));
	log->tpm_version = 1;

	if ((log->fd = open(eventlog_path, O_RDONLY)) < 0)
		fatal("Unable to open TPM eventlog \"%s\"\n", eventlog_path);
	return log;
}

void
event_log_close(tpm_event_log_reader_t *log)
{
	close(log->fd);
	free(log);
}

static void
event_log_read_digest(tpm_event_log_reader_t *log, tpm_evdigest_t *dgst, int tpm_hash_algo_id)
{
	const tpm_algo_info_t *algo;

	if (!(algo = event_log_get_algo_info(log, tpm_hash_algo_id)))
		fatal("Unable to handle event log entry for unknown hash algorithm %u\n", tpm_hash_algo_id);

	__read_exactly(log->fd, dgst->data, algo->digest_size);

	dgst->algo_id = tpm_hash_algo_id;
	dgst->size = algo->digest_size;
}

static void
event_log_resize_pcrs(tpm_event_t *ev, unsigned int count)
{
	if (count > 32)
		fatal("Bad number of PCRs in TPM event record (%u)\n", count);

	ev->pcr_values = calloc(count, sizeof(tpm_evdigest_t));
	if (ev->pcr_values == NULL)
		fatal("out of memory");
	ev->pcr_count = count;
}

static void
event_log_read_pcrs_tpm1(tpm_event_log_reader_t *log, tpm_event_t *ev)
{
	event_log_resize_pcrs(ev, 1);
	event_log_read_digest(log, &ev->pcr_values[0], __TPM2_ALG_SHA1);
}

static void
event_log_read_pcrs_tpm2(tpm_event_log_reader_t *log, tpm_event_t *ev)
{
	uint32_t i, count;

	__read_u32le(log->fd, &count);
	event_log_resize_pcrs(ev, count);

	for (i = 0; i < count; ++i) {
		uint16_t algo_id;

		__read_u16le(log->fd, &algo_id);
		event_log_read_digest(log, &ev->pcr_values[i], algo_id);
	}
}

tpm_event_t *
event_log_read_next(tpm_event_log_reader_t *log)
{
	tpm_event_t *ev;
	uint32_t event_size;

again:
	ev = calloc(1, sizeof(*ev));
	if (!__read_u32le_or_eof(log->fd, &ev->pcr_index)) {
		free(ev);
		return NULL;
	}

	__read_u32le(log->fd, &ev->event_type);

	ev->file_offset = lseek(log->fd, 0, SEEK_CUR);

	if (log->tpm_version == 1) {
		event_log_read_pcrs_tpm1(log, ev);
	} else {
		event_log_read_pcrs_tpm2(log, ev);
	}

	__read_u32le(log->fd, &event_size);
	if (event_size > 8192)
		fatal("Oversized TPM2 event log entry with %u bytes of data\n", event_size);

	ev->event_data = calloc(1, event_size);
	ev->event_size = event_size;
	__read_exactly(log->fd, ev->event_data, event_size);


	if (log->tpm_version == 1 && ev->event_type == TPM2_EVENT_NO_ACTION
	 && !strncmp((char *) ev->event_data, "Spec ID Event03", 16)) {
		printf("Detected TPMv2 event log\n");

		if (!__tpm_event_parse_tcg2_info(ev, &log->tcg2_info))
			fatal("Unable to parse TCG2 magic event header");

		log->tpm_version = log->tcg2_info.spec_version_major;
		free(ev);
		goto again;
	}

	return ev;
}

const char *
tpm_event_type_to_string(unsigned int event_type)
{
	static char buffer[16];

	switch (event_type) {
	case TPM2_EVENT_PREBOOT_CERT:
		return "EVENT_PREBOOT_CERT";
	case TPM2_EVENT_POST_CODE:
		return "EVENT_POST_CODE";
	case TPM2_EVENT_UNUSED:
		return "EVENT_UNUSED";
	case TPM2_EVENT_NO_ACTION:
		return "EVENT_NO_ACTION";
	case TPM2_EVENT_SEPARATOR:
		return "EVENT_SEPARATOR";
	case TPM2_EVENT_ACTION:
		return "EVENT_ACTION";
	case TPM2_EVENT_EVENT_TAG:
		return "EVENT_EVENT_TAG";
	case TPM2_EVENT_S_CRTM_CONTENTS:
		return "EVENT_S_CRTM_CONTENTS";
	case TPM2_EVENT_S_CRTM_VERSION:
		return "EVENT_S_CRTM_VERSION";
	case TPM2_EVENT_CPU_MICROCODE:
		return "EVENT_CPU_MICROCODE";
	case TPM2_EVENT_PLATFORM_CONFIG_FLAGS:
		return "EVENT_PLATFORM_CONFIG_FLAGS";
	case TPM2_EVENT_TABLE_OF_DEVICES:
		return "EVENT_TABLE_OF_DEVICES";
	case TPM2_EVENT_COMPACT_HASH:
		return "EVENT_COMPACT_HASH";
	case TPM2_EVENT_IPL:
		return "EVENT_IPL";
	case TPM2_EVENT_IPL_PARTITION_DATA:
		return "EVENT_IPL_PARTITION_DATA";
	case TPM2_EVENT_NONHOST_CODE:
		return "EVENT_NONHOST_CODE";
	case TPM2_EVENT_NONHOST_CONFIG:
		return "EVENT_NONHOST_CONFIG";
	case TPM2_EVENT_NONHOST_INFO:
		return "EVENT_NONHOST_INFO";
	case TPM2_EVENT_OMIT_BOOT_DEVICE_EVENTS:
		return "EVENT_OMIT_BOOT_DEVICE_EVENTS";
	case TPM2_EFI_EVENT_BASE:
		return "EFI_EVENT_BASE";
	case TPM2_EFI_VARIABLE_DRIVER_CONFIG:
		return "EFI_VARIABLE_DRIVER_CONFIG";
	case TPM2_EFI_VARIABLE_BOOT:
		return "EFI_VARIABLE_BOOT";
	case TPM2_EFI_BOOT_SERVICES_APPLICATION:
		return "EFI_BOOT_SERVICES_APPLICATION";
	case TPM2_EFI_BOOT_SERVICES_DRIVER:
		return "EFI_BOOT_SERVICES_DRIVER";
	case TPM2_EFI_RUNTIME_SERVICES_DRIVER:
		return "EFI_RUNTIME_SERVICES_DRIVER";
	case TPM2_EFI_GPT_EVENT:
		return "EFI_GPT_EVENT";
	case TPM2_EFI_ACTION:
		return "EFI_ACTION";
	case TPM2_EFI_PLATFORM_FIRMWARE_BLOB:
		return "EFI_PLATFORM_FIRMWARE_BLOB";
	case TPM2_EFI_HANDOFF_TABLES:
		return "EFI_HANDOFF_TABLES";
	case TPM2_EFI_PLATFORM_FIRMWARE_BLOB2:
		return "EFI_PLATFORM_FIRMWARE_BLOB2";
	case TPM2_EFI_HANDOFF_TABLES2:
		return "EFI_HANDOFF_TABLES2";
	case TPM2_EFI_VARIABLE_BOOT2:
		return "EFI_VARIABLE_BOOT2";
	case TPM2_EFI_HCRTM_EVENT:
		return "EFI_HCRTM_EVENT";
	case TPM2_EFI_VARIABLE_AUTHORITY:
		return "EFI_VARIABLE_AUTHORITY";
	case TPM2_EFI_SPDM_FIRMWARE_BLOB:
		return "EFI_SPDM_FIRMWARE_BLOB";
	case TPM2_EFI_SPDM_FIRMWARE_CONFIG:
		return "EFI_SPDM_FIRMWARE_CONFIG";
	}

	snprintf(buffer, sizeof(buffer), "0x%x", event_type);
	return buffer;
}

const tpm_evdigest_t *
tpm_event_get_digest(const tpm_event_t *ev, const char *algo_name)
{
	unsigned int i;
	int algo_id;

	if ((algo_id = event_log_get_named_algo(algo_name)) < 0)
		fatal("Unknown algo name \"%s\"\n", algo_name);

	for (i = 0; i < ev->pcr_count; ++i) {
		const tpm_evdigest_t *md = &ev->pcr_values[i];

		if (md->algo_id == algo_id)
			return md;
	}

	return NULL;
}

void
tpm_event_print(tpm_event_t *ev)
{
	const unsigned char *data;
	tpm_parsed_event_t *parsed;
	unsigned int i;

	printf("%05lx: ", ev->file_offset);
	printf("event type=%s pcr=%d digests=%d data=%u: ",
			tpm_event_type_to_string(ev->event_type),
			ev->pcr_index, ev->pcr_count, ev->event_size);

	if (ev->event_size > 100) {
		printf(" <hidden>");
	} else {
		data = (const unsigned char *) ev->event_data;
		for (i = 0; i < ev->event_size; ++i) {
			unsigned char cc = data[i];

			if (isalnum(cc) || ispunct(cc) || cc == ' ' || cc == '\t')
				putc(cc, stdout);
			else
				printf("\\%o", cc);
		}
	}
	putc('\n', stdout);

	parsed = tpm_event_parse(ev);
	if (parsed)
		tpm_parsed_event_print(parsed);

	for (i = 0; i < ev->pcr_count; ++i) {
		const tpm_evdigest_t *d = &ev->pcr_values[i];
		const tpm_algo_info_t *algo;
		unsigned int j;

		algo = event_well_known_algo_info(d->algo_id);
		if (algo)
			printf("  %-10s", algo->openssl_name);
		else
			printf("  %-10u", d->algo_id);

		for (j = 0 ; j < d->size; ++j)
			printf("%02x", d->data[j]);
		printf("\n");
	}
}

static tpm_parsed_event_t *
tpm_parsed_event_new(unsigned int event_type)
{
	tpm_parsed_event_t *parsed;

	parsed = calloc(1, sizeof(*parsed));
	parsed->event_type = event_type;
	return parsed;
}

static void
tpm_parsed_event_free(tpm_parsed_event_t *parsed)
{
	if (parsed->destroy)
		parsed->destroy(parsed);
	memset(parsed, 0, sizeof(*parsed));
	free(parsed);
}

void
tpm_parsed_event_print(tpm_parsed_event_t *parsed)
{
	if (parsed && parsed->print)
		parsed->print(parsed);
}

typedef struct bufparser {
	unsigned int		pos, len;
	const unsigned char *	data;
} bufparser_t;

static inline void
bufparser_init(bufparser_t *bp, const void *data, unsigned int len)
{
	bp->data = (const unsigned char *) data;
	bp->len = len;
	bp->pos = 0;
}

static inline bool
bufparser_skip(bufparser_t *bp, unsigned int count)
{
	if (count > bp->len - bp->pos)
		return false;

	bp->pos += count;
	return true;
}

static inline bool
bufparser_available(const bufparser_t *bp)
{
	return bp->len - bp->pos;
}

static inline bool
bufparser_eof(const bufparser_t *bp)
{
	return bufparser_available(bp) == 0;
}

static inline bool
bufparser_get(bufparser_t *bp, void *dest, unsigned int count)
{
	if (count > bp->len - bp->pos)
		return false;

	memcpy(dest, bp->data + bp->pos, count);
	bp->pos += count;
	return true;
}

static inline bool
bufparser_get_u8(bufparser_t *bp, uint8_t *vp)
{
	if (!bufparser_get(bp, vp, sizeof(*vp)))
		return false;
	return true;
}

static inline bool
bufparser_get_u16le(bufparser_t *bp, uint16_t *vp)
{
	if (!bufparser_get(bp, vp, sizeof(*vp)))
		return false;
	*vp = le16toh(*vp);
	return true;
}

static inline bool
bufparser_get_u32le(bufparser_t *bp, uint32_t *vp)
{
	if (!bufparser_get(bp, vp, sizeof(*vp)))
		return false;
	*vp = le32toh(*vp);
	return true;
}

static inline bool
bufparser_get_u64le(bufparser_t *bp, uint64_t *vp)
{
	if (!bufparser_get(bp, vp, sizeof(*vp)))
		return false;
	*vp = le64toh(*vp);
	return true;
}

static inline bool
bufparser_get_size(bufparser_t *bp, size_t *vp)
{
	if (sizeof(*vp) == 4) {
		uint32_t size;

		if (!bufparser_get_u32le(bp, &size))
			return false;
		*vp = size;
	} else
	if (sizeof(*vp) == 8) {
		uint64_t size;

		if (!bufparser_get_u64le(bp, &size))
			return false;
		*vp = size;
	} else
		return false;

	return true;
}

static inline bool
bufparser_get_buffer(bufparser_t *bp, unsigned int count, bufparser_t *res)
{
	if (count > bp->len - bp->pos)
		return false;

	bufparser_init(res, bp->data + bp->pos, count);
	bp->pos += count;
	return true;
}

static inline bool
__convert_utf16le(char *in_string, size_t in_bytes, char *out_string, size_t out_bytes)
{
	iconv_t *ctx;

	ctx = iconv_open("utf8", "utf16le");

	while (in_bytes) {
		size_t converted;

		converted = iconv(ctx,
				&in_string, &in_bytes,
				&out_string, &out_bytes);
		if (converted < 0) {
			perror("iconv");
			return false;
		}
	}
	*out_string = '\0';

	return true;
}

static inline char *
bufparser_get_utf16le(bufparser_t *bp, size_t len)
{
	char *utf16, *utf8, *result = NULL;

	utf16 = malloc(2 * (len + 1));
	if (!utf16)
		fatal("out of memory");

	if (!bufparser_get(bp, utf16, 2 * len))
		return NULL;

	utf8 = malloc(4 * (len + 1));

	if (__convert_utf16le(utf16, 2 * len, utf8, 4 * len))
		result = strdup(utf8);

	free(utf16);
	free(utf8);

	return result;
}

static inline const char *
print_guid(const unsigned char *guid)
{
	static char buf[64];

	snprintf(buf, sizeof(buf),
			"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
			guid[0], guid[1], guid[2], guid[3], guid[4], guid[5], guid[6], guid[7],
			guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]);
	return buf;
}

/*
 * Process EFI_VARIABLE events
 */
static void
__tpm_event_efi_variable_destroy(tpm_parsed_event_t *parsed)
{
}

static void
__tpm_event_efi_variable_print(tpm_parsed_event_t *parsed)
{
	printf("  --> EFI variable %s-%s: %u bytes of data\n",
			parsed->efi_variable_event.variable_name,
			print_guid(parsed->efi_variable_event.variable_guid),
			parsed->efi_variable_event.len);
}

static bool
__tpm_event_parse_tcg2_info(tpm_event_t *ev, struct tpm_event_log_tcg2_info *info)
{
	bufparser_t buf;
	uint32_t i, algo_info_count;

	bufparser_init(&buf, ev->event_data, ev->event_size);

	/* skip over magic signature string */
	bufparser_skip(&buf, 16);

	if (!bufparser_get_u32le(&buf, &info->platform_class)
	 || !bufparser_get_u8(&buf, &info->spec_version_major)
	 || !bufparser_get_u8(&buf, &info->spec_version_minor)
	 || !bufparser_get_u8(&buf, &info->spec_errata)
	 || !bufparser_get_u8(&buf, &info->uintn_size)
	 || !bufparser_get_u32le(&buf, &algo_info_count)
	   )
		return false;

	for (i = 0; i < algo_info_count; ++i) {
		uint16_t algo_id, algo_size;
		const tpm_algo_info_t *wk;

		if (!bufparser_get_u16le(&buf, &algo_id)
		 || !bufparser_get_u16le(&buf, &algo_size))
			return false;

		if (algo_id >= TPM2_ALG_MAX)
			continue;

		if ((wk = event_well_known_algo_info(algo_id)) == NULL) {
			info->algorithms[algo_id].digest_size = algo_size;
		} else if (wk->digest_size != algo_size) {
			fprintf(stderr, "Conflicting digest sizes for %s: %u versus %u\n",
					wk->openssl_name, wk->digest_size, algo_size);
		} else
			/* NOP */ ;
	}

	return true;
}

static bool
__tpm_event_parse_efi_variable(tpm_event_t *ev, tpm_parsed_event_t *parsed, bufparser_t *bp)
{
	uint64_t name_len, data_len;

	parsed->destroy = __tpm_event_efi_variable_destroy;
	parsed->print = __tpm_event_efi_variable_print;

	if (!bufparser_get(bp, parsed->efi_variable_event.variable_guid, sizeof(parsed->efi_variable_event.variable_guid)))
		return false;

	if (!bufparser_get_u64le(bp, &name_len) || !bufparser_get_u64le(bp, &data_len))
		return false;

	if (!(parsed->efi_variable_event.variable_name = bufparser_get_utf16le(bp, name_len)))
		return false;

	parsed->efi_variable_event.data = malloc(data_len);
	if (!bufparser_get(bp, parsed->efi_variable_event.data, data_len))
		return false;
	parsed->efi_variable_event.len = data_len;

	return parsed;
}

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

static const char *
__tpm_event_efi_device_path_item_harddisk_uuid(const struct efi_device_path_item *item)
{
	static char uuid[64];

	if (item->type == TPM2_EFI_DEVPATH_TYPE_MEDIA_DEVICE
	 && item->subtype == TPM2_EFI_DEVPATH_MEDIA_SUBTYPE_HARDDRIVE) {
		const unsigned char *data = item->data + 20;
		uint32_t w0;
		uint16_t hw0, hw1;

		w0 = le32toh(((uint32_t *) data)[0]);
		hw0 = le32toh(((uint16_t *) data)[2]);
		hw1 = le32toh(((uint16_t *) data)[3]);
		snprintf(uuid, sizeof(uuid), "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
				w0, hw0, hw1,
				data[8], data[9],
				data[10], data[11], data[12],
				data[13], data[14], data[15]
				);
		return uuid;
	}

	return NULL;
}

static const char *
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

static void
__tpm_event_efi_device_path_print(const efi_device_path_t *path)
{
	const struct efi_device_path_item *item;
	unsigned int i;

	for (i = 0, item = path->entries; i < path->count; ++i, ++item) {
		__tpm_event_efi_device_path_item_print(item);
	}
}

static void
__tpm_event_efi_bsa_destroy(tpm_parsed_event_t *parsed)
{
}

static void
__tpm_event_efi_bsa_print(tpm_parsed_event_t *parsed)
{
#if 0
	printf("BSA image loc=%Lx", (unsigned long long) parsed->efi_bsa_event.image_location);
	printf(" len=%Lx", (unsigned long long) parsed->efi_bsa_event.image_length);
	printf(" lt-addr=%Lx", (unsigned long long) parsed->efi_bsa_event.image_lt_address);
	printf("\n");
#endif

	printf("Boot Service Application; device path:\n");
	__tpm_event_efi_device_path_print(&parsed->efi_bsa_event.device_path);
}

static bool
__tpm_event_parse_eft_device_path(efi_device_path_t *path, bufparser_t *bp)
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

static bool
__tpm_event_parse_efi_bsa(tpm_event_t *ev, tpm_parsed_event_t *parsed, bufparser_t *bp)
{
	size_t device_path_len;
	bufparser_t path_buf;

	parsed->destroy = __tpm_event_efi_bsa_destroy;
	parsed->print = __tpm_event_efi_bsa_print;

	if (!bufparser_get_u64le(bp, &parsed->efi_bsa_event.image_location)
	 || !bufparser_get_size(bp, &parsed->efi_bsa_event.image_length)
	 || !bufparser_get_size(bp, &parsed->efi_bsa_event.image_lt_address)
	 || !bufparser_get_size(bp, &device_path_len)
	 || !bufparser_get_buffer(bp, device_path_len, &path_buf))
		return false;

	if (!__tpm_event_parse_eft_device_path(&parsed->efi_bsa_event.device_path, &path_buf))
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

	printf("Analyzing device path:\n");
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

			printf("device is %s\n", dev_path);
			drop_string(dev_ret);
			*dev_ret = dev_path;
		}

		if ((filepath = __tpm_event_efi_device_path_item_file_path(item)) != NULL) {
			printf("file is %s\n", filepath);
			assign_string(path_ret, filepath);
		}
	}

	return *dev_ret && *path_ret;
}

static bool
__tpm_event_parse(tpm_event_t *ev, tpm_parsed_event_t *parsed)
{
	bufparser_t buf;

	bufparser_init(&buf, ev->event_data, ev->event_size);

	switch (ev->event_type) {
	case TPM2_EFI_VARIABLE_AUTHORITY:
	case TPM2_EFI_VARIABLE_BOOT:
	case TPM2_EFI_VARIABLE_DRIVER_CONFIG:
		return __tpm_event_parse_efi_variable(ev, parsed, &buf);

	case TPM2_EFI_BOOT_SERVICES_APPLICATION:
		return __tpm_event_parse_efi_bsa(ev, parsed, &buf);
	}

	return false;
}

tpm_parsed_event_t *
tpm_event_parse(tpm_event_t *ev)
{
	if (!ev->__parsed) {
		tpm_parsed_event_t *parsed;

		parsed = tpm_parsed_event_new(ev->event_type);
		if (__tpm_event_parse(ev, parsed))
			ev->__parsed = parsed;
		else
			tpm_parsed_event_free(parsed);
	}

	return ev->__parsed;
}
