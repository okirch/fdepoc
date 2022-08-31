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

#include "eventlog.h"
#include "util.h"

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

enum {
	__TPM2_ALG_SHA1 = 4,
	__TPM2_ALG_SHA256 = 11,
	__TPM2_ALG_SHA384 = 12,
	__TPM2_ALG_SHA512 = 13,

	TPM2_ALG_MAX
};

struct tpm_event_log_reader {
	unsigned int		tpm_version;
	int			fd;
};

static const tpm_algo_info_t *
event_log_get_algo_info(unsigned int algo_id)
{
	static tpm_algo_info_t		tpm_algorithms[TPM2_ALG_MAX] = {
		[__TPM2_ALG_SHA1]		= {	"sha1",			20	},
		[__TPM2_ALG_SHA256]	= {	"sha256",		32	},
		[__TPM2_ALG_SHA384]	= {	"sha284",		48	},
		[__TPM2_ALG_SHA512]	= {	"sha512",		64	},
	};
	tpm_algo_info_t *algo;

	if (algo_id >= TPM2_ALG_MAX)
		return NULL;

	algo = &tpm_algorithms[algo_id];
	if (algo->openssl_name == NULL)
		return NULL;

	return algo;
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

	if (!(algo = event_log_get_algo_info(tpm_hash_algo_id)))
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
		/* TBD: parse the TCG2 header event */

			log->tpm_version = 2;
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

		algo = event_log_get_algo_info(d->algo_id);
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
bufparser_get(bufparser_t *bp, void *dest, unsigned int count)
{
	if (count > bp->len - bp->pos)
		return false;

	memcpy(dest, bp->data + bp->pos, count);
	bp->pos += count;
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
	static buf[64];

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
