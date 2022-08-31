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

#ifndef EVENTLOG_H
#define EVENTLOG_H

typedef struct tpm_evdigest {
	unsigned int		algo_id;
	unsigned int		size;
	unsigned char		data[128];
} tpm_evdigest_t;

typedef struct tpm_event {
	struct tpm_event *	next;

	long			file_offset;
	struct tpm_parsed_event *__parsed;

	uint32_t		pcr_index;
	uint32_t		event_type;

	unsigned int		pcr_count;
	tpm_evdigest_t *	pcr_values;

	unsigned int		event_size;
	void *			event_data;
} tpm_event_t;

typedef struct tpm_algo_info {
	const char *		openssl_name;
	unsigned int		digest_size;
} tpm_algo_info_t;

enum {
	TPM2_EVENT_PREBOOT_CERT              = 0x00000000,
	TPM2_EVENT_POST_CODE                 = 0x00000001,
	TPM2_EVENT_UNUSED                    = 0x00000002,
	TPM2_EVENT_NO_ACTION                 = 0x00000003,
	TPM2_EVENT_SEPARATOR                 = 0x00000004,
	TPM2_EVENT_ACTION                    = 0x00000005,
	TPM2_EVENT_EVENT_TAG                 = 0x00000006,
	TPM2_EVENT_S_CRTM_CONTENTS           = 0x00000007,
	TPM2_EVENT_S_CRTM_VERSION            = 0x00000008,
	TPM2_EVENT_CPU_MICROCODE             = 0x00000009,
	TPM2_EVENT_PLATFORM_CONFIG_FLAGS     = 0x0000000A,
	TPM2_EVENT_TABLE_OF_DEVICES          = 0x0000000B,
	TPM2_EVENT_COMPACT_HASH              = 0x0000000C,
	TPM2_EVENT_IPL                       = 0x0000000D,
	TPM2_EVENT_IPL_PARTITION_DATA        = 0x0000000E,
	TPM2_EVENT_NONHOST_CODE              = 0x0000000F,
	TPM2_EVENT_NONHOST_CONFIG            = 0x00000010,
	TPM2_EVENT_NONHOST_INFO              = 0x00000011,
	TPM2_EVENT_OMIT_BOOT_DEVICE_EVENTS   = 0x00000012,

	TPM2_EFI_EVENT_BASE                  = 0x80000000,
	TPM2_EFI_VARIABLE_DRIVER_CONFIG      = 0x80000001,
	TPM2_EFI_VARIABLE_BOOT               = 0x80000002,
	TPM2_EFI_BOOT_SERVICES_APPLICATION   = 0x80000003,
	TPM2_EFI_BOOT_SERVICES_DRIVER        = 0x80000004,
	TPM2_EFI_RUNTIME_SERVICES_DRIVER     = 0x80000005,
	TPM2_EFI_GPT_EVENT                   = 0x80000006,
	TPM2_EFI_ACTION                      = 0x80000007,
	TPM2_EFI_PLATFORM_FIRMWARE_BLOB      = 0x80000008,
	TPM2_EFI_HANDOFF_TABLES              = 0x80000009,
	TPM2_EFI_PLATFORM_FIRMWARE_BLOB2     = 0x8000000A,
	TPM2_EFI_HANDOFF_TABLES2             = 0x8000000B,
	TPM2_EFI_VARIABLE_BOOT2              = 0x8000000C,
	TPM2_EFI_HCRTM_EVENT                 = 0x80000010,
	TPM2_EFI_VARIABLE_AUTHORITY          = 0x800000E0,
	TPM2_EFI_SPDM_FIRMWARE_BLOB          = 0x800000E1,
	TPM2_EFI_SPDM_FIRMWARE_CONFIG        = 0x800000E2,
};

/*
 * Parsed event types
 */
typedef struct tpm_parsed_event {
	unsigned int		event_type;
	void			(*destroy)(struct tpm_parsed_event *);
	void			(*print)(struct tpm_parsed_event *);

	union {
		struct {
			unsigned char	variable_guid[16];
			char *		variable_name;
			unsigned int	len;
			void *		data;
		} efi_variable_event;
	};
} tpm_parsed_event_t;

typedef struct tpm_event_log_reader tpm_event_log_reader_t;

extern tpm_event_log_reader_t *	event_log_open(void);
extern void			event_log_close(tpm_event_log_reader_t *log);
extern tpm_event_t *		event_log_read_next(tpm_event_log_reader_t *log);
extern void			tpm_event_print(tpm_event_t *ev);
extern tpm_parsed_event_t *	tpm_event_parse(tpm_event_t *ev);
extern void			tpm_parsed_event_print(tpm_parsed_event_t *parsed);

#endif /* EVENTLOG_H */
