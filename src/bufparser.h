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

#ifndef BUFPARSER_H
#define BUFPARSER_H

#include "util.h"

typedef struct bufparser {
	unsigned int		pos, len;
	const unsigned char *	data;
} bufparser_t;

typedef struct bufbuilder {
	unsigned int		pos, size;
	unsigned char *		data;
} bufbuilder_t;

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

	if (__convert_from_utf16le(utf16, 2 * len, utf8, 4 * len))
		result = strdup(utf8);

	free(utf16);
	free(utf8);

	return result;
}

static inline void
bufbuilder_init(bufbuilder_t *bp, void *data, unsigned int len)
{
	bp->data = (unsigned char *) data;
	bp->size = len;
	bp->pos = 0;
}

static inline bufbuilder_t *
bufbuilder_alloc(unsigned long size)
{
	bufbuilder_t *bp;

	size = (size + 7) & ~7UL;
	bp = malloc(sizeof(*bp) + size);
	bufbuilder_init(bp, (void *) (bp + 1), size);

	return bp;
}

static inline void
bufbuilder_free(bufbuilder_t *bp)
{
	free(bp);
}

static inline unsigned int
bufbuilder_tailroom(const bufbuilder_t *bp)
{
	return bp->size - bp->pos;
}

static inline bool
bufbuilder_put(bufbuilder_t *bp, const void *src, unsigned int count)
{
	if (count > bp->size - bp->pos)
		return false;

	memcpy(bp->data + bp->pos, src, count);
	bp->pos += count;
	return true;
}

static inline bool
bufbuilder_put_u8(bufbuilder_t *bp, uint8_t *vp)
{
	return bufbuilder_put(bp, vp, sizeof(*vp));
}

static inline bool
bufbuilder_put_u16le(bufbuilder_t *bp, uint16_t value)
{
	uint16_t tmp = htole16(value);

	return bufbuilder_put(bp, &tmp, sizeof(tmp));
}

static inline bool
bufbuilder_put_u32le(bufbuilder_t *bp, uint32_t value)
{
	uint32_t tmp = htole32(value);

	return bufbuilder_put(bp, &tmp, sizeof(tmp));
}

static inline bool
bufbuilder_put_u64le(bufbuilder_t *bp, uint64_t value)
{
	uint64_t tmp = htole64(value);

	return bufbuilder_put(bp, &tmp, sizeof(tmp));
}

static inline bool
bufbuilder_put_utf16le(bufbuilder_t *bp, char *utf8, unsigned int *size_ret_p)
{
	unsigned int len = strlen(utf8);
	char *utf16;
	bool ok = true;

	utf16 = malloc(2 * len);
	if (!utf16)
		fatal("out of memory");

	ok = __convert_to_utf16le(utf8, len, utf16, 2 * len);
	if (ok)
		ok = bufbuilder_put(bp, utf16, 2 * len);
	if (ok && size_ret_p)
		*size_ret_p = 2 * len;

	free(utf16);
	return ok;
}

static inline bool
bufbuilder_put_size(bufbuilder_t *bp, size_t value)
{
	if (sizeof(value) == 4) {
		return bufbuilder_put_u32le(bp, value);
	} else
	if (sizeof(value) == 8) {
		return bufbuilder_put_u64le(bp, value);
	} else
		return false;

	return true;
}


#endif /* BUFPARSER_H */
