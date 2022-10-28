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
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <ctype.h>
#include <iconv.h>
#include <limits.h>

#include <tss2/tss2_tpm2_types.h>

#include "eventlog.h"
#include "bufparser.h"
#include "runtime.h"
#include "util.h"


/*
 * Process EFI_VARIABLE events
 */
static void
__tpm_event_efi_variable_destroy(tpm_parsed_event_t *parsed)
{
}

static void
__tpm_event_efi_variable_print(tpm_parsed_event_t *parsed, tpm_event_bit_printer *print_fn)
{
	print_fn("  --> EFI variable %s: %u bytes of data\n",
			tpm_efi_variable_event_extract_full_varname(parsed),
			parsed->efi_variable_event.len);
}

static bool
__tpm_event_marshal_efi_variable(buffer_t *bp, const tpm_parsed_event_t *parsed, const void *raw_data, unsigned int raw_data_len)
{
	unsigned int var_len, name_len;

	if (!buffer_put(bp, parsed->efi_variable_event.variable_guid, sizeof(parsed->efi_variable_event.variable_guid)))
		return false;

	var_len = strlen(parsed->efi_variable_event.variable_name);
	if (!buffer_put_u64le(bp, var_len)
	 || !buffer_put_u64le(bp, raw_data_len)
	 || !buffer_put_utf16le(bp, parsed->efi_variable_event.variable_name, &name_len)
	 || !buffer_put(bp, raw_data, raw_data_len))
		return false;

	if (name_len != 2 * var_len)
		return false;

	return true;
}

static buffer_t *
__tpm_event_efi_variable_build_event(const tpm_parsed_event_t *parsed, const void *raw_data, unsigned int raw_data_len)
{
	buffer_t *bp;

	/* The marshal buffer needs to hold
	 * GUID, 2 * UINT64, plus the UTF16 encoding of the variable name, plus the raw efivar value */
	bp = buffer_alloc_write(16 + 8 + 8 +
			+ 2 * strlen(parsed->efi_variable_event.variable_name)
			+ raw_data_len);

	if (!__tpm_event_marshal_efi_variable(bp, parsed, raw_data, raw_data_len)) {
		debug("Failed to marshal EFI variable %s\n", parsed->efi_variable_event.variable_name);
		buffer_free(bp);
		return NULL;
	}

	return bp;
}

enum {
	HASH_STRATEGY_EVENT,
	HASH_STRATEGY_DATA,
};

static const tpm_evdigest_t *
__tpm_event_efi_variable_rehash(const tpm_event_t *ev, const tpm_parsed_event_t *parsed, tpm_event_log_rehash_ctx_t *ctx)
{
	const tpm_algo_info_t *algo = ctx->algo;
	const char *var_name;
	buffer_t *file_data, *event_data = NULL, *data_to_hash = NULL;
	const tpm_evdigest_t *md, *old_md;
	int hash_strategy;

	if (!(var_name = tpm_efi_variable_event_extract_full_varname(parsed)))
		fatal("Unable to extract EFI variable name from EFI_VARIABLE event\n");

	old_md = tpm_event_get_digest(ev, algo->openssl_name);
	if (old_md == NULL) {
		debug("Event does not provide a digest for algorithm %s\n", algo->openssl_name);
		return NULL;
	}

	if (!strcmp(var_name, "SbatLevel-605dab50-e046-4300-abb6-3dd810dd8b23") ||
	    !strcmp(var_name, "Shim-605dab50-e046-4300-abb6-3dd810dd8b23") ||
	    !strcmp(var_name, "MokDBState-605dab50-e046-4300-abb6-3dd810dd8b23") ||
	    !strcmp(var_name, "MokSBState-605dab50-e046-4300-abb6-3dd810dd8b23") ||
	    !strcmp(var_name, "MokList-605dab50-e046-4300-abb6-3dd810dd8b23") ||
	    !strcmp(var_name, "MokListX-605dab50-e046-4300-abb6-3dd810dd8b23") ||
	    !strcmp(var_name, "MokListTrusted-605dab50-e046-4300-abb6-3dd810dd8b23")) {
		debug("EFI variable %s is protected from kernel runtime; assuming it did not change\n", var_name);
		return old_md;
	}

	/* UEFI implementations seem to differ in what they hash. Some Dell firmwares
	 * always seem to hash the entire event. The OVMF firmware, on the other hand,
	 * hashes the log for EFI_VARIABLE_DRIVER_CONFIG events, and just the data for
	 * other variable events. */
	md = digest_compute(algo, ev->event_data, ev->event_size);
	if (digest_equal(old_md, md)) {
		debug("  Firmware hashed entire event data\n");
		hash_strategy = HASH_STRATEGY_EVENT;
	} else {
		md = digest_compute(algo, parsed->efi_variable_event.data, parsed->efi_variable_event.len);
		if (digest_equal(old_md, md)) {
			debug("  Firmware hashed variable data\n");
			hash_strategy = HASH_STRATEGY_DATA;
		} else {
			debug("  I'm lost.\n");
			hash_strategy = HASH_STRATEGY_DATA; /* no idea what would be right */
		}
	}

	file_data = runtime_read_efi_variable(var_name);
	if (file_data == NULL)
		return NULL;

	if (hash_strategy == HASH_STRATEGY_EVENT) {
		event_data = __tpm_event_efi_variable_build_event(parsed,
				buffer_read_pointer(file_data),
				buffer_available(file_data));
		if (event_data == NULL)
			fatal("Unable to re-marshal EFI variable for hashing\n");

		if (opt_debug > 1) {
			debug("  Remarshaled event for EFI variable %s:\n", var_name);
			hexdump(buffer_read_pointer(event_data),
				buffer_available(event_data),
				debug, 8);
		 }

		data_to_hash = event_data;
	} else {
		data_to_hash = file_data;
	}

	md = digest_compute(algo,
			buffer_read_pointer(data_to_hash),
			buffer_available(data_to_hash));

	buffer_free(file_data);
	if (event_data)
		buffer_free(event_data);
	return md;
}

bool
__tpm_event_parse_efi_variable(tpm_event_t *ev, tpm_parsed_event_t *parsed, buffer_t *bp)
{
	uint64_t name_len, data_len;

	parsed->destroy = __tpm_event_efi_variable_destroy;
	parsed->print = __tpm_event_efi_variable_print;
	parsed->rehash = __tpm_event_efi_variable_rehash;

	if (!buffer_get(bp, parsed->efi_variable_event.variable_guid, sizeof(parsed->efi_variable_event.variable_guid)))
		return false;

	if (!buffer_get_u64le(bp, &name_len) || !buffer_get_u64le(bp, &data_len))
		return false;

	if (!(parsed->efi_variable_event.variable_name = buffer_get_utf16le(bp, name_len)))
		return false;

	parsed->efi_variable_event.data = malloc(data_len);
	if (!buffer_get(bp, parsed->efi_variable_event.data, data_len))
		return false;
	parsed->efi_variable_event.len = data_len;

	return parsed;
}

const char *
tpm_efi_variable_event_extract_full_varname(const tpm_parsed_event_t *parsed)
{
	static char varname[256];

	snprintf(varname, sizeof(varname), "%s-%s", 
			parsed->efi_variable_event.variable_name,
			tpm_event_decode_uuid(parsed->efi_variable_event.variable_guid));
	return varname;
}

