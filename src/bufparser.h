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

#endif /* BUFPARSER_H */
