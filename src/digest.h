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


#ifndef DIGEST_H
#define DIGEST_H

#include <openssl/evp.h>

typedef struct tpm_evdigest {
	unsigned int		algo_id;
	unsigned int		size;
	unsigned char		data[EVP_MAX_MD_SIZE];
} tpm_evdigest_t;

typedef struct tpm_algo_info {
	unsigned int		tcg_id;
	const char *		openssl_name;
	unsigned int		digest_size;
} tpm_algo_info_t;

extern const tpm_algo_info_t *		digest_by_tpm_alg(unsigned int algo_id);
extern const tpm_algo_info_t *		digest_by_name(const char *name);
extern const char *			digest_print(const tpm_evdigest_t *);
extern const char *			digest_print_value(const tpm_evdigest_t *);

extern const tpm_algo_info_t *		__digest_by_tpm_alg(unsigned int, const tpm_algo_info_t *, unsigned int);

#endif /* DIGEST_H */
