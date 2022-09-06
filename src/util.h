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

#ifndef UTIL_H
#define UTIL_H

#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>

#include <openssl/evp.h>

typedef struct tpm_evdigest {
	unsigned int		algo_id;
	unsigned int		size;
	unsigned char		data[EVP_MAX_MD_SIZE];
} tpm_evdigest_t;


#define debug(msg ...) \
	do {					\
		if (opt_debug)			\
			printf(msg);		\
	} while (0)

extern bool	opt_debug;

static inline void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "Fatal: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(2);
}

static inline void
drop_string(char **var)
{
	if (*var) {
		free(*var);
		*var = NULL;
	}
}

static inline void
assign_string(char **var, const char *string)
{
	drop_string(var);
	if (string)
		*var = strdup(string);
}

extern bool		parse_pcr_index(const char *word, unsigned int *ret);
extern bool		parse_hexdigit(const char **pos, unsigned char *ret);
extern bool		parse_octet(const char **pos, unsigned char *ret);
extern unsigned int	parse_octet_string(const char *string, unsigned char *buffer, size_t bufsz);
extern const tpm_evdigest_t *parse_digest(const char *string, const char *algo);


#endif /* UTIL_H */
