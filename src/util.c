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
#include <iconv.h>

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

static inline void
pcr_mask_set(uint32_t *mask_p, unsigned int index)
{
	if (index >= 32)
		fatal("PCR index %u out of range\n", index);
	*mask_p |= (1 << index);
}

bool
parse_pcr_mask(const char *word, uint32_t *ret)
{
	const char *orig_string = word;
	unsigned int value;
	const char *end;

	if (!strcmp(word, "all")) {
		*ret = ~0;
		return true;
	}

	*ret = 0;
	while (*word) {
		if (!isdigit(*word))
			return false;

		value = strtoul(word, (char **) &end, 10);
		if (*end == '-' && isdigit(end[1])) {
			unsigned int last;

			last = strtoul(end + 1, (char **) &end, 10);
			while (value < last)
				pcr_mask_set(ret, value++);
		}

		pcr_mask_set(ret, value);

		while (*end == ',')
			++end;
		word = end;
	}

	if (*word) {
		fprintf(stderr, "Unable to parse PCR mask \"%s\"\n", orig_string);
		return false;
	}
	return true;
}

const char *
print_pcr_mask(unsigned int mask)
{
	static char buffer[128];
	unsigned int i;
	char *pos;

	buffer[0] = '\0';
	pos = buffer;

	for (i = 0; i < 32; ) {
		if (mask & (1 << i)) {
			if (pos != buffer)
				*pos++ = ',';
			if (mask & (1 << (i + 1))) {
				pos += sprintf(pos, "%u-", i);
				while (i < 32 && (mask & (1 << (i + 1))))
					++i;
			}
			pos += sprintf(pos, "%u", i);
		}

		i += 1;
	}

	return buffer;
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

const char *
print_octet_string(const unsigned char *data, unsigned int len)
{
	static char buffer[3 * 64 + 1];

	if (len < 32) {
		unsigned int i;
		char *s;

		s = buffer;
		for (i = 0; i < len; ++i) {
			if (i)
				*s++ = ':';
			sprintf(s, "%02x", data[i]);
			s += 2;
		}
		*s = '\0';
	} else {
		snprintf(buffer, sizeof(buffer), "<%u bytes of data>", len);
	}

	return buffer;

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

/*
 * Conversion between UTF-8 and UTF-16LE for EFI event log
 */
bool
__convert_from_utf16le(char *in_string, size_t in_bytes, char *out_string, size_t out_bytes)
{
	iconv_t *ctx;

	ctx = iconv_open("utf8", "utf16le");

	while (in_bytes) {
		size_t converted;

		converted = iconv(ctx,
				&in_string, &in_bytes,
				&out_string, &out_bytes);
		if (converted == (size_t) -1) {
			perror("iconv");
			return false;
		}
	}
	*out_string = '\0';

	return true;
}

bool
__convert_to_utf16le(char *in_string, size_t in_bytes, char *out_string, size_t out_bytes)
{
	iconv_t *ctx;

	ctx = iconv_open("utf16le", "utf8");

	while (in_bytes) {
		size_t converted;

		converted = iconv(ctx,
				&in_string, &in_bytes,
				&out_string, &out_bytes);
		if (converted == (size_t) -1) {
			perror("iconv");
			return false;
		}
	}

	return true;
}

/*
 * Helper for measuring exec times
 */
static double
relative_timing(void)
{
	static struct timespec t0;
	struct timespec now, delta;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (t0.tv_sec == 0 && t0.tv_nsec == 0)
		t0 = now;

	delta.tv_sec = now.tv_sec - t0.tv_sec;
	delta.tv_nsec = now.tv_nsec - t0.tv_nsec;

	return delta.tv_sec + 1e-9 * delta.tv_nsec;
}

double
timing_begin(void)
{
	return relative_timing();
}

double
timing_since(double since)
{
	return relative_timing() - since;
}
