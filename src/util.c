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

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "util.h"
#include "digest.h"

bool
parse_pcr_index(const char *word, unsigned int *ret)
{
	unsigned int value;
	const char *end;

	value = strtoul(word, (char **) &end, 10);
	if (*end) {
		fprintf(stderr, "Unable to parse PCR index \"%s\"\n", word);
		return false;
	}

	*ret = value;
	return true;
}

bool
parse_hexdigit(const char **pos, unsigned char *ret)
{
	char cc = *(*pos)++;
	unsigned int octet;

	if (isdigit(cc))
		octet = cc - '0';
	else if ('a' <= cc && cc <= 'f')
		octet = cc - 'a' + 10;
	else if ('A' <= cc && cc <= 'F')
		octet = cc - 'A' + 10;
	else
		return false;

	*ret = (*ret << 4) | octet;
	return true;
}

bool
parse_octet(const char **pos, unsigned char *ret)
{
	return parse_hexdigit(pos, ret) && parse_hexdigit(pos, ret);
}

unsigned int
parse_octet_string(const char *string, unsigned char *buffer, size_t bufsz)
{
	const char *orig_string = string;
	unsigned int i;

	for (i = 0; *string; ++i) {
		if (i >= bufsz) {
			debug("%s: octet string too long for buffer: \"%s\"\n", __func__, orig_string);
			return 0;
		}
		if (!parse_octet(&string, &buffer[i])) {
			debug("%s: bad octet near offset %d \"%s\"\n", __func__, 2 * i, orig_string);
			return 0;
		}
	}

	return i;
}

const tpm_evdigest_t *
parse_digest(const char *string, const char *algo)
{
	static const tpm_algo_info_t *algo_info;
	static tpm_evdigest_t md;

	if (!(algo_info = digest_by_name(algo)))
		fatal("%s: unknown digest name \"%s\"\n", __func__, algo);

	memset(&md, 0, sizeof(md));
	md.algo = algo_info;

	md.size = parse_octet_string(string, md.data, sizeof(md.data));
	if (md.size != algo_info->digest_size) {
		debug("Cannot parse %s digest \"%s\" - wrong size %u; expected %u\n",
				algo, string, md.size, algo_info->digest_size);
		return NULL;
	}

	return &md;
}

void
hexdump(const void *data, size_t size, void (*print_fn)(const char *, ...), unsigned int indent)
{
	const unsigned char *bytes = data;
	unsigned int i, j, bytes_per_line;
	char octets[32 * 3 + 1];
	char ascii[32 + 1];

	for (i = 0; i < size; i += 32) {
		char *pos;

		if ((bytes_per_line = size - i) > 32)
			bytes_per_line = 32;

		pos = octets;
		for (j = 0; j < 32; ++j) {
			if (j < bytes_per_line)
				sprintf(pos, " %02x", bytes[i + j]);
			else
				sprintf(pos, "   ");
			pos += 3;
		}

		pos = ascii;
		for (j = 0; j < bytes_per_line; ++j) {
			unsigned char cc = bytes[i + j];

			if (isalnum(cc) || ispunct(cc))
				*pos++ = cc;
			else
				*pos++ = '.';

			*pos = '\0';
		}

		print_fn("%*.*s%04x %-96s %-s\n",
				(int) indent, (int) indent, "",
				i, octets, ascii);
	}
}
