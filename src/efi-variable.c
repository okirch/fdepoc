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
#include "util.h"


/*
 * Process EFI_VARIABLE events
 */
static void
__tpm_event_efi_variable_destroy(tpm_parsed_event_t *parsed)
{
}

static void
__tpm_event_efi_variable_print(tpm_parsed_event_t *parsed, tpm_event_bit_printer *print_fn)
{
	print_fn("  --> EFI variable %s: %u bytes of data\n",
			tpm_efi_variable_event_extract_full_varname(parsed),
			parsed->efi_variable_event.len);
}

static bool
__tpm_event_marshal_efi_variable(buffer_t *bp, const tpm_parsed_event_t *parsed, const void *raw_data, unsigned int raw_data_len)
{
	unsigned int var_len, name_len;

	if (!buffer_put(bp, parsed->efi_variable_event.variable_guid, sizeof(parsed->efi_variable_event.variable_guid)))
		return false;

	var_len = strlen(parsed->efi_variable_event.variable_name);
	if (!buffer_put_u64le(bp, var_len)
	 || !buffer_put_u64le(bp, raw_data_len)
	 || !buffer_put_utf16le(bp, parsed->efi_variable_event.variable_name, &name_len)
	 || !buffer_put(bp, raw_data, raw_data_len))
		return false;

	if (name_len != 2 * var_len)
		return false;

	return true;
}

static buffer_t *
__tpm_event_efi_variable_rebuild(const tpm_parsed_event_t *parsed, const void *raw_data, unsigned int raw_data_len)
{
	buffer_t *bp;

	/* The marshal buffer needs to hold
	 * GUID, 2 * UINT64, plus the UTF16 encoding of the variable name, plus the raw efivar value */
	bp = buffer_alloc_write(16 + 8 + 8 +
			+ 2 * strlen(parsed->efi_variable_event.variable_name)
			+ raw_data_len);

	if (!__tpm_event_marshal_efi_variable(bp, parsed, raw_data, raw_data_len)) {
		debug("Failed to marshal EFI variable %s\n", parsed->efi_variable_event.variable_name);
		buffer_free(bp);
		return NULL;
	}

	return bp;
}

bool
__tpm_event_parse_efi_variable(tpm_event_t *ev, tpm_parsed_event_t *parsed, buffer_t *bp)
{
	uint64_t name_len, data_len;

	parsed->destroy = __tpm_event_efi_variable_destroy;
	parsed->print = __tpm_event_efi_variable_print;
	parsed->rebuild = __tpm_event_efi_variable_rebuild;

	if (!buffer_get(bp, parsed->efi_variable_event.variable_guid, sizeof(parsed->efi_variable_event.variable_guid)))
		return false;

	if (!buffer_get_u64le(bp, &name_len) || !buffer_get_u64le(bp, &data_len))
		return false;

	if (!(parsed->efi_variable_event.variable_name = buffer_get_utf16le(bp, name_len)))
		return false;

	parsed->efi_variable_event.data = malloc(data_len);
	if (!buffer_get(bp, parsed->efi_variable_event.data, data_len))
		return false;
	parsed->efi_variable_event.len = data_len;

	return parsed;
}

const char *
tpm_efi_variable_event_extract_full_varname(tpm_parsed_event_t *parsed)
{
	static char varname[256];

	snprintf(varname, sizeof(varname), "%s-%s", 
			parsed->efi_variable_event.variable_name,
			tpm_event_decode_uuid(parsed->efi_variable_event.variable_guid));
	return varname;
}

