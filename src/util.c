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
