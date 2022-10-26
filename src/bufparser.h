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

#include <string.h>
#include "util.h"

typedef struct buffer {
	unsigned int		rpos;
	unsigned int		wpos;
	unsigned int		size;
	unsigned char *		data;
} buffer_t;

static inline void
buffer_init_read(buffer_t *bp, void *data, unsigned int len)
{
	bp->data = (unsigned char *) data;
	bp->rpos = 0;
	bp->wpos = len;
	bp->size = len;
}

static inline bool
buffer_skip(buffer_t *bp, unsigned int count)
{
	if (count > bp->wpos - bp->rpos)
		return false;

	bp->rpos += count;
	return true;
}

static inline const void *
buffer_read_pointer(const buffer_t *bp)
{
	return bp->data + bp->rpos;
}

static inline unsigned int
buffer_available(const buffer_t *bp)
{
	return bp->wpos - bp->rpos;
}

static inline bool
buffer_eof(const buffer_t *bp)
{
	return buffer_available(bp) == 0;
}

static inline bool
buffer_seek_read(buffer_t *bp, unsigned int new_pos)
{
	if (new_pos > bp->wpos)
		return false;

	bp->rpos = new_pos;
	return true;
}

static inline bool
buffer_get(buffer_t *bp, void *dest, unsigned int count)
{
	if (count > bp->wpos - bp->rpos)
		return false;

	memcpy(dest, bp->data + bp->rpos, count);
	bp->rpos += count;
	return true;
}

static inline bool
buffer_get_u8(buffer_t *bp, uint8_t *vp)
{
	if (!buffer_get(bp, vp, sizeof(*vp)))
		return false;
	return true;
}

static inline bool
buffer_get_u16le(buffer_t *bp, uint16_t *vp)
{
	if (!buffer_get(bp, vp, sizeof(*vp)))
		return false;
	*vp = le16toh(*vp);
	return true;
}

static inline bool
buffer_get_u32le(buffer_t *bp, uint32_t *vp)
{
	if (!buffer_get(bp, vp, sizeof(*vp)))
		return false;
	*vp = le32toh(*vp);
	return true;
}

static inline bool
buffer_get_u64le(buffer_t *bp, uint64_t *vp)
{
	if (!buffer_get(bp, vp, sizeof(*vp)))
		return false;
	*vp = le64toh(*vp);
	return true;
}

static inline bool
buffer_get_size(buffer_t *bp, size_t *vp)
{
	if (sizeof(*vp) == 4) {
		uint32_t size;

		if (!buffer_get_u32le(bp, &size))
			return false;
		*vp = size;
	} else
	if (sizeof(*vp) == 8) {
		uint64_t size;

		if (!buffer_get_u64le(bp, &size))
			return false;
		*vp = size;
	} else
		return false;

	return true;
}

static inline bool
buffer_get_buffer(buffer_t *bp, unsigned int count, buffer_t *res)
{
	if (count > bp->wpos - bp->rpos)
		return false;

	buffer_init_read(res, bp->data + bp->rpos, count);
	bp->rpos += count;
	return true;
}

static inline char *
buffer_get_utf16le(buffer_t *bp, size_t len)
{
	char *utf16, *utf8, *result = NULL;

	utf16 = malloc(2 * (len + 1));
	if (!utf16)
		fatal("out of memory");

	if (!buffer_get(bp, utf16, 2 * len))
		return NULL;

	utf8 = malloc(4 * (len + 1));

	if (__convert_from_utf16le(utf16, 2 * len, utf8, 4 * len))
		result = strdup(utf8);

	free(utf16);
	free(utf8);

	return result;
}

static inline void
buffer_init_write(buffer_t *bp, void *data, unsigned int len)
{
	bp->data = (unsigned char *) data;
	bp->rpos = 0;
	bp->wpos = 0;
	bp->size = len;
}

static inline buffer_t *
buffer_alloc_write(unsigned long size)
{
	buffer_t *bp;

	size = (size + 7) & ~7UL;
	bp = malloc(sizeof(*bp) + size);
	buffer_init_write(bp, (void *) (bp + 1), size);

	return bp;
}

static inline void
buffer_free(buffer_t *bp)
{
	free(bp);
}

static inline void *
buffer_write_pointer(const buffer_t *bp)
{
	return bp->data + bp->wpos;
}

static inline unsigned int
buffer_tailroom(const buffer_t *bp)
{
	return bp->size - bp->wpos;
}

static inline bool
buffer_put(buffer_t *bp, const void *src, unsigned int count)
{
	if (count > bp->size - bp->wpos)
		return false;

	memcpy(bp->data + bp->wpos, src, count);
	bp->wpos += count;
	return true;
}

static inline bool
buffer_put_u8(buffer_t *bp, uint8_t *vp)
{
	return buffer_put(bp, vp, sizeof(*vp));
}

static inline bool
buffer_put_u16le(buffer_t *bp, uint16_t value)
{
	uint16_t tmp = htole16(value);

	return buffer_put(bp, &tmp, sizeof(tmp));
}

static inline bool
buffer_put_u32le(buffer_t *bp, uint32_t value)
{
	uint32_t tmp = htole32(value);

	return buffer_put(bp, &tmp, sizeof(tmp));
}

static inline bool
buffer_put_u64le(buffer_t *bp, uint64_t value)
{
	uint64_t tmp = htole64(value);

	return buffer_put(bp, &tmp, sizeof(tmp));
}

static inline bool
buffer_put_utf16le(buffer_t *bp, char *utf8, unsigned int *size_ret_p)
{
	unsigned int len = strlen(utf8);
	char *utf16;
	bool ok = true;

	utf16 = malloc(2 * len);
	if (!utf16)
		fatal("out of memory");

	ok = __convert_to_utf16le(utf8, len, utf16, 2 * len);
	if (ok)
		ok = buffer_put(bp, utf16, 2 * len);
	if (ok && size_ret_p)
		*size_ret_p = 2 * len;

	free(utf16);
	return ok;
}

static inline bool
buffer_put_size(buffer_t *bp, size_t value)
{
	if (sizeof(value) == 4) {
		return buffer_put_u32le(bp, value);
	} else
	if (sizeof(value) == 8) {
		return buffer_put_u64le(bp, value);
	} else
		return false;

	return true;
}


#endif /* BUFPARSER_H */
