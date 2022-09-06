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
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <limits.h>
#include <assert.h>

#include "util.h"
#include "eventlog.h"

enum {
	__TPM2_ALG_sha1 = 4,
	__TPM2_ALG_sha256 = 11,
	__TPM2_ALG_sha384 = 12,
	__TPM2_ALG_sha512 = 13,

	TPM2_ALG_MAX
};

#define DESCRIBE_ALGO(name, size) \
	__DESCRIBE_ALGO(name, __TPM2_ALG_ ## name, size)
#define __DESCRIBE_ALGO(name, id, size) \
	[id]	= { id,		#name,		size }
static tpm_algo_info_t		tpm_algorithms[TPM2_ALG_MAX] = {
	DESCRIBE_ALGO(sha1,		20),
	DESCRIBE_ALGO(sha256,		32),
	DESCRIBE_ALGO(sha384,		48),
	DESCRIBE_ALGO(sha512,		64),
};

const tpm_algo_info_t *
__digest_by_tpm_alg(unsigned int algo_id, const tpm_algo_info_t *algorithms, unsigned int num_algoritms)
{
	const tpm_algo_info_t *algo;

	if (algo_id >= num_algoritms)
		return NULL;

	algo = &algorithms[algo_id];
	if (algo->digest_size == 0)
		return NULL;

	return algo;
}

const tpm_algo_info_t *
digest_by_tpm_alg(unsigned int algo_id)
{
	return __digest_by_tpm_alg(algo_id, tpm_algorithms, TPM2_ALG_MAX);
}

const tpm_algo_info_t *
digest_by_name(const char *name)
{
	const tpm_algo_info_t *algo;
	int i;

	for (i = 0, algo = tpm_algorithms; i < TPM2_ALG_MAX; ++i, ++algo) {
		if (algo->openssl_name && !strcasecmp(algo->openssl_name, name))
			return algo;
	}

	return NULL;
}

const char *
digest_print(const tpm_evdigest_t *md)
{
	static char buffer[1024];
	const tpm_algo_info_t *algo;

	if ((algo = digest_by_tpm_alg(md->algo_id)) != NULL)
		snprintf(buffer, sizeof(buffer), "%s: %s", algo->openssl_name, digest_print_value(md));
	else
		snprintf(buffer, sizeof(buffer), "TPM2_ALG_%u: %s", md->algo_id, digest_print_value(md));
	return buffer;
}

const char *
digest_print_value(const tpm_evdigest_t *md)
{
	static char buffer[2 * sizeof(md->data) + 1];
	unsigned int i;

	assert(md->size <= sizeof(md->data));
        for (i = 0; i < md->size; i++)
                sprintf(buffer + 2 * i, "%02x", md->data[i]);
	return buffer;
}
