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
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <ctype.h>
#include <tss2_fapi.h>

#include "util.h"
#include "runtime.h"
#include "pcr.h"
#include "digest.h"
#include "testcase.h"

void
pcr_bank_initialize(tpm_pcr_bank_t *bank, unsigned int pcr_mask, const tpm_algo_info_t *algo)
{
	unsigned int i;

	memset(bank, 0, sizeof(*bank));
	bank->algo_name = algo->openssl_name;
	bank->pcr_mask = pcr_mask;

	for (i = 0; i < PCR_BANK_REGISTER_MAX; ++i) {
		tpm_evdigest_t *pcr = &bank->pcr[i];

		pcr->size = algo->digest_size;
		pcr->algo = algo;
	}
}

bool
pcr_bank_wants_pcr(tpm_pcr_bank_t *bank, unsigned int index)
{
	return !!(bank->pcr_mask & (1 << index));
}

void
pcr_bank_mark_valid(tpm_pcr_bank_t *bank, unsigned int index)
{
	bank->valid_mask |= (1 << index);
}

bool
pcr_bank_register_is_valid(const tpm_pcr_bank_t *bank, unsigned int index)
{
	return (bank->valid_mask & (1 << index));
}

tpm_evdigest_t *
pcr_bank_get_register(tpm_pcr_bank_t *bank, unsigned int index, const char *algo)
{
	if (algo && strcasecmp(algo, bank->algo_name))
		return NULL;

	if (!pcr_bank_wants_pcr(bank, index))
		return NULL;

	return &bank->pcr[index];
}

void
pcr_bank_set_locality(tpm_pcr_bank_t *bank, unsigned int pcr_index, uint8_t locality)
{
	tpm_evdigest_t *pcr;

	if (!pcr_bank_register_is_valid(bank, pcr_index)) {
		error("Unable to extend PCR %s:%u: register was not initialized\n",
				bank->algo_name, pcr_index);
		return;
	}

	pcr = &bank->pcr[pcr_index];

	memset(pcr->data, 0, pcr->size);
	pcr->data[pcr->size-1] = locality;
}

void
pcr_bank_init_from_zero(tpm_pcr_bank_t *bank)
{
	unsigned int i;

	for (i = 0; i < PCR_BANK_REGISTER_MAX; ++i) {
		tpm_evdigest_t *pcr;

		if (!(pcr = pcr_bank_get_register(bank, i, NULL)))
			continue;

		memset(pcr->data, 0, sizeof(pcr->data));
		pcr_bank_mark_valid(bank, i);
	}
}

void
pcr_bank_init_from_snapshot_fp(FILE *fp, tpm_pcr_bank_t *bank)
{
	char linebuf[256];

	while (fgets(linebuf, sizeof(linebuf), fp) != NULL) {
		unsigned int index;
		const char *algo, *value;
		tpm_evdigest_t *pcr;
		unsigned int len;
		char *w;

		// debug("=> %s", linebuf);
		if (!(w = strtok(linebuf, " \t\n")))
			continue;

		if (!parse_pcr_index(w, &index)
		 || !(algo = strtok(NULL, " \t\n")))
			continue;

		// debug("inspecting %u:%s\n", index, algo);
		if ((pcr = pcr_bank_get_register(bank, index, algo)) == NULL)
			continue;

		if (!(value = strtok(NULL, " \t\n")))
			continue;

		len = parse_octet_string(value, pcr->data, sizeof(pcr->data));
		if (len == 0)
			continue;

		if (len != pcr->size) {
			debug("Found entry for %s:%u, but value has wrong size %u (expected %u)\n",
				bank->algo_name, index, len, pcr->size);
			continue;
		}

		pcr_bank_mark_valid(bank, index);
	}

	fclose(fp);
}

void
pcr_bank_init_from_snapshot(tpm_pcr_bank_t *bank, const char *efivar_path)
{
	FILE *fp;

	debug("Trying to find PCR values in %s\n", efivar_path);
	if (!(fp = fopen(efivar_path, "r")))
		fatal("Unable to open \"%s\": %m\n", efivar_path);

	pcr_bank_init_from_snapshot_fp(fp, bank);
}

static void
fapi_error(const char *func, int rc)
{
	fatal("TPM2: function %s returns %d\n", func, rc);
}

void
pcr_bank_init_from_current(tpm_pcr_bank_t *bank)
{
	const char *algo_name = bank->algo_name;
	FAPI_CONTEXT *context = NULL;
	uint8_t *digests[8] = { NULL };
	size_t digest_sizes[8] = { 0 };
	unsigned int i;
	int rc;
	FILE *recording, *playback;

	if (strcmp(algo_name, "sha256"))
		fatal("Cannot initialize from current TPM values for digest algorithm %s - not implemented\n",
				algo_name);

	playback = runtime_maybe_playback_pcrs();
	if (playback) {
		pcr_bank_init_from_snapshot_fp(playback, bank);
		return;
	}

	rc = Fapi_Initialize(&context, NULL);
	if (rc != 0)
		fapi_error("Fapi_Initialize", rc);

	recording = runtime_maybe_record_pcrs();

	for (i = 0; i < 24; ++i) {
		tpm_evdigest_t *pcr;

		if (!(pcr = pcr_bank_get_register(bank, i, "sha256")))
			continue;

		/* FIXME: how does this function select a PCR bank?
		 * The answer is: it doesn't. The proper way to obtain current
		 * values for eg sha1 would be to use ESYS_PCR_Read() instead.
		 */
		rc = Fapi_PcrRead(context, i, digests, digest_sizes, NULL);
		if (rc)
			fapi_error("Fapi_PcrRead", rc);

		if (pcr->size != digest_sizes[0])
			fatal("Could not initialize predictor for PCR %s:%u: initial hash value has size %u (expected %u)\n",
					algo_name, i,
					(int) digest_sizes[0], pcr->size);
		memcpy(pcr->data, digests[0], pcr->size);

		if (digest_is_invalid(pcr)) {
			if (opt_debug > 1)
				debug("ignoring PCR %u; %s\n", i, digest_print(pcr));
			continue;
		}

		pcr_bank_mark_valid(bank, i);
		Fapi_Free(digests[0]);

		if (recording)
			fprintf(recording, "%02u sha256 %s\n", i, digest_print_value(pcr));
	}

	if (recording)
		fclose(recording);
}

