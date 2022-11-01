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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>

#include "oracle.h"
#include "eventlog.h"
#include "bufparser.h"
#include "runtime.h"
#include "authenticode.h"
#include "digest.h"
#include "util.h"


/*
 * Process EFI Boot Service Application events
 */
static const tpm_evdigest_t *	__tpm_event_efi_bsa_rehash(const tpm_event_t *, const tpm_parsed_event_t *, tpm_event_log_rehash_ctx_t *);
static bool			__tpm_event_efi_bsa_extract_location(tpm_parsed_event_t *parsed);


static void
__tpm_event_efi_bsa_destroy(tpm_parsed_event_t *parsed)
{
	__tpm_event_efi_device_path_destroy(&parsed->efi_bsa_event.device_path);

	drop_string(&parsed->efi_bsa_event.efi_partition);
	drop_string(&parsed->efi_bsa_event.efi_application);
}

static void
__tpm_event_efi_bsa_print(tpm_parsed_event_t *parsed, tpm_event_bit_printer *print_fn)
{
#if 0
	print_fn("BSA image loc=%Lx", (unsigned long long) parsed->efi_bsa_event.image_location);
	print_fn(" len=%Lx", (unsigned long long) parsed->efi_bsa_event.image_length);
	print_fn(" lt-addr=%Lx", (unsigned long long) parsed->efi_bsa_event.image_lt_address);
	print_fn("\n");
#endif

	print_fn("Boot Service Application; device path:\n");
	__tpm_event_efi_device_path_print(&parsed->efi_bsa_event.device_path, print_fn);
}

static const char *
__tpm_event_efi_bsa_describe(const tpm_parsed_event_t *parsed)
{
	static char buffer[1024];
	char *result;

	if (parsed->efi_bsa_event.efi_application) {
		snprintf(buffer, sizeof(buffer), "EFI Boot Service Application %s", parsed->efi_bsa_event.efi_application);
		result = buffer;
	} else {
		result = "EFI Boot Service Application";
	}

	return result;
}

bool
__tpm_event_parse_efi_bsa(tpm_event_t *ev, tpm_parsed_event_t *parsed, buffer_t *bp)
{
	size_t device_path_len;
	buffer_t path_buf;

	parsed->destroy = __tpm_event_efi_bsa_destroy;
	parsed->print = __tpm_event_efi_bsa_print;
	parsed->describe = __tpm_event_efi_bsa_describe;
	parsed->rehash = __tpm_event_efi_bsa_rehash;

	if (!buffer_get_u64le(bp, &parsed->efi_bsa_event.image_location)
	 || !buffer_get_size(bp, &parsed->efi_bsa_event.image_length)
	 || !buffer_get_size(bp, &parsed->efi_bsa_event.image_lt_address)
	 || !buffer_get_size(bp, &device_path_len)
	 || !buffer_get_buffer(bp, device_path_len, &path_buf))
		return false;

	if (!__tpm_event_parse_efi_device_path(&parsed->efi_bsa_event.device_path, &path_buf))
		return false;

	__tpm_event_efi_bsa_extract_location(parsed);

	return true;
}

bool
__tpm_event_efi_bsa_extract_location(tpm_parsed_event_t *parsed)
{
	struct efi_bsa_event *evspec = &parsed->efi_bsa_event;
	const struct efi_device_path *efi_path;
	const struct efi_device_path_item *item;
	unsigned int i;

	efi_path = &parsed->efi_bsa_event.device_path;
	for (i = 0, item = efi_path->entries; i < efi_path->count; ++i, ++item) {
		char pathbuf[PATH_MAX];
		const char *uuid, *filepath;

		if ((uuid = __tpm_event_efi_device_path_item_harddisk_uuid(item)) != NULL) {
			char *dev_path;

			/* FIXME: should go to runtime.c */
			snprintf(pathbuf, sizeof(pathbuf), "/dev/disk/by-partuuid/%s", uuid);
			if ((dev_path = realpath(pathbuf, NULL)) == NULL) {
				error("Cannot find device for partition with uuid %s\n", uuid);
				return false;
			}

			drop_string(&evspec->efi_partition);
			evspec->efi_partition = dev_path;
		}

		if ((filepath = __tpm_event_efi_device_path_item_file_path(item)) != NULL) {
			assign_string(&evspec->efi_application, filepath);
		}
	}

	return true;
}

static const tpm_evdigest_t *
__pecoff_rehash_old(tpm_event_log_rehash_ctx_t *ctx, const char *filename)
{
	const char *algo_name = ctx->algo->openssl_name;
	char cmdbuf[8192], linebuf[1024];
	const tpm_evdigest_t *md = NULL;
	FILE *fp;
	int exitcode;

	snprintf(cmdbuf, sizeof(cmdbuf),
			"pesign --hash --in %s --digest_type %s",
			filename, algo_name);

	debug("Executing command: %s\n", cmdbuf);
	if ((fp = popen(cmdbuf, "r")) == NULL)
		fatal("Unable to run command: %s\n", cmdbuf);

	while (fgets(linebuf, sizeof(linebuf), fp) != NULL) {
		char *w;

		/* line must start with "hash:" */
		if (!(w = strtok(linebuf, " \t\n:")) || strcmp(w, "hash"))
			continue;

		if (!(w = strtok(NULL, " \t\n")))
			fatal("cannot parse pesign output\n");

		if (!(md = parse_digest(w, algo_name)))
			fatal("unable to parse %s digest printed by pesign: \"%s\"\n", algo_name, w);

		debug("  pesign digest: %s\n", digest_print(md));
		break;
	}

	exitcode = pclose(fp);
	if (exitcode == -1)
		fatal("pclose failed: %m\n");
	else if (!WIFEXITED(exitcode))
		fatal("pesign command failed\n");
	else if (WEXITSTATUS(exitcode) != 0)
		fatal("pesign command failed with %d\n", WEXITSTATUS(exitcode));

	return md;
}

static const tpm_evdigest_t *
__pecoff_rehash_new(tpm_event_log_rehash_ctx_t *ctx, const char *filename)
{
	digest_ctx_t *digest;
	const tpm_evdigest_t *md;
	buffer_t *buffer;

	debug("Computing authenticode digest using built-in PECOFF parser\n");
	if (!(buffer = runtime_read_file(filename, 0)))
		return NULL;

	digest = digest_ctx_new(ctx->algo);

	md = authenticode_get_digest(buffer, digest);

	buffer_free(buffer);
	digest_ctx_free(digest);

	return md;
}

static const tpm_evdigest_t *
__efi_application_rehash(tpm_event_log_rehash_ctx_t *ctx, const char *device_path, const char *file_path)
{
	const tpm_evdigest_t *md;
	file_locator_t *loc;
	const char *fullpath;

	loc = runtime_locate_file(device_path, file_path);
	if (!loc)
		fatal("Failed to locate EFI application (%s)%s", device_path, file_path);

	fullpath = file_locator_get_full_path(loc);
	if (ctx->use_pesign) {
		md = __pecoff_rehash_old(ctx, fullpath);
	} else {
		md = __pecoff_rehash_new(ctx, fullpath);
	}

	file_locator_free(loc);

	return md;
}

buffer_t *
efi_application_extract_signer(const char *device_path, const char *file_path)
{
	buffer_t *result = NULL;
	file_locator_t *loc;

	loc = runtime_locate_file(device_path, file_path);
	if (!loc)
		fatal("Failed to locate EFI application (%s)%s", device_path, file_path);

	result = authenticode_get_signer(file_locator_get_full_path(loc));
	file_locator_free(loc);

	return result;
}

static const tpm_evdigest_t *
__tpm_event_efi_bsa_rehash(const tpm_event_t *ev, const tpm_parsed_event_t *parsed, tpm_event_log_rehash_ctx_t *ctx)
{
	const struct efi_bsa_event *evspec = &parsed->efi_bsa_event;

	if (evspec->efi_partition)
		assign_string(&ctx->efi_partition, evspec->efi_partition);

	/* Some BSA events do not refer to files, but to some data blobs residing somewhere on a device.
	 * We're not yet prepared to handle these, so we hope the user doesn't mess with them, and
	 * return the original digest from the event log.
	 */
	if (!evspec->efi_application) {
		debug("Unable to locate boot service application - probably not a file\n");
		return tpm_event_get_digest(ev, ctx->algo->openssl_name);
	}

	return __efi_application_rehash(ctx, ctx->efi_partition, evspec->efi_application);
}
