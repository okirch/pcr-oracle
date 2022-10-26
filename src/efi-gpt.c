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
#include <sys/mount.h>
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

#include "oracle.h"
#include "eventlog.h"
#include "bufparser.h"
#include "runtime.h"
#include "util.h"


/*
 * Process EFI GPT events
 */
static const tpm_evdigest_t *	__tpm_event_efi_gpt_rehash(const tpm_event_t *, const tpm_parsed_event_t *, tpm_event_log_rehash_ctx_t *);


static void
__tpm_event_efi_gpt_destroy(tpm_parsed_event_t *parsed)
{
	drop_string(&parsed->efi_gpt_event.disk_device);
}

static const char *
__tpm_event_efi_gpt_describe(const tpm_parsed_event_t *parsed)
{
	return "EFI GPT";
}

bool
__tpm_event_parse_efi_gpt(tpm_event_t *ev, tpm_parsed_event_t *parsed, buffer_t *bp)
{
	parsed->destroy = __tpm_event_efi_gpt_destroy;
	parsed->describe = __tpm_event_efi_gpt_describe;
	parsed->rehash = __tpm_event_efi_gpt_rehash;

	return true;
}

static buffer_t *
__tpm_event_efi_gpt_rebuild(const char *device)
{
	static const unsigned int gpt_max_entries = 64;
	static unsigned char gpt_type_uuid_empty[16] = { 0 };
	buffer_t *buffer = NULL, *result = NULL;
	const void *hdr_base_addr;
	const void *gpt_entry_ptr[gpt_max_entries];
	unsigned char gpt_sig[8];
	uint32_t gpt_hdr_len, gpt_num_entries, gpt_entry_size;
	unsigned int num_tbl_bytes, i, num_valid_entries;
	int fd = -1;

	if ((fd = runtime_blockdev_open(device)) < 0) {
		error("Unable to open disk device %s: %m\n", device);
		goto failed;
	}

	if (!(buffer = runtime_blockdev_read_lba(fd, 1, 1))) {
		error("%s: unable to read GPT sector\n", device);
		goto failed;
	}

	hdr_base_addr = buffer_read_pointer(buffer);
	if (opt_debug > 2) {
		debug("GPT header\n");
		hexdump(hdr_base_addr, 0x5c, debug, 8);
	}

	if (!buffer_get(buffer, gpt_sig, 8)
	 || memcmp(gpt_sig, "EFI PART", 8))
		goto bad_header;

	if (!buffer_seek_read(buffer, 0x0c)
	 || !buffer_get_u32le(buffer, &gpt_hdr_len)
	 || gpt_hdr_len != 0x5c)
		goto bad_header;

	if (!buffer_seek_read(buffer, 0x50)
	 || !buffer_get_u32le(buffer, &gpt_num_entries)
	 || !buffer_get_u32le(buffer, &gpt_entry_size))
		goto bad_header;

	num_tbl_bytes = (gpt_num_entries * gpt_entry_size + 511) & ~511;

	/* Start building the event. The first part is the GPT header */
	result = buffer_alloc_write(gpt_hdr_len + 8 + num_tbl_bytes);
	buffer_put(result, hdr_base_addr, gpt_hdr_len);
	buffer_free(buffer);

	if (!(buffer = runtime_blockdev_read_lba(fd, 2, runtime_blockdev_bytes_to_sectors(num_tbl_bytes)))) {
		error("%s: unable to read GPT sector\n", device);
		goto failed;
	}

	num_valid_entries = 0;
	for (i = 0; i < gpt_num_entries; ++i) {
		if (!buffer_seek_read(buffer, i * gpt_entry_size))
			goto failed;

		if (!memcmp(buffer_read_pointer(buffer), gpt_type_uuid_empty, sizeof(gpt_type_uuid_empty)))
			continue;

		if (num_valid_entries >= gpt_max_entries) {
			error("too many GPT entries for my little brain\n");
			goto failed;
		}

		gpt_entry_ptr[num_valid_entries++] = buffer_read_pointer(buffer);

		if (opt_debug > 2) {
			debug("GPT entry %u\n", i);
			hexdump(buffer_read_pointer(buffer), gpt_entry_size, debug, 8);
		}
	}

	if (!buffer_put_u64le(result, num_valid_entries))
		goto failed;
	for (i = 0; i < num_valid_entries; ++i) {
		if (!buffer_put(result, gpt_entry_ptr[i], gpt_entry_size))
			goto failed;
	}

out:
	if (fd >= 0)
		close(fd);
	if (buffer)
		buffer_free(buffer);
	return result;

bad_header:
	error("%s: bad GPT header\n", device);

failed:
	if (result)
		buffer_free(result);
	result = NULL;
	goto out;
}

static const tpm_evdigest_t *
__tpm_event_efi_gpt_rehash(const tpm_event_t *ev, const tpm_parsed_event_t *parsed, tpm_event_log_rehash_ctx_t *ctx)
{
	const tpm_evdigest_t *md = NULL;
	buffer_t *buffer = NULL;
	char *device;

	if (ctx->efi_partition == NULL) {
		error("Cannot determine EFI partition from event log\n");
		/* FIXME: just use the device that holds /boot/efi? */
		return NULL;
	}

	if (!(device = runtime_disk_for_partition(ctx->efi_partition))) {
		error("Unable to determine disk for partition %s\n", ctx->efi_partition);
		return NULL;
	}

	debug("  Trying to re-hash GPT for %s\n", device);
	buffer = __tpm_event_efi_gpt_rebuild(device);
	if (buffer == NULL)
		goto out;

	if (opt_debug > 1) {
		debug("  Re-built GPT event data:\n");
		hexdump(buffer_read_pointer(buffer), buffer_available(buffer), debug, 8);
	}

	md = digest_buffer(ctx->algo, buffer);

out:
	if (buffer)
		buffer_free(buffer);
	free(device);
	return md;
}
