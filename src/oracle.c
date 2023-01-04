/*
 *   Copyright (C) 2022, 2023 SUSE LLC
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

#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "oracle.h"
#include "util.h"
#include "eventlog.h"
#include "bufparser.h"
#include "runtime.h"
#include "pcr.h"
#include "digest.h"
#include "testcase.h"

enum {
	ACTION_NONE,
	ACTION_PREDICT,
	ACTION_CREATE_AUTH_POLICY,
	ACTION_STORE_PUBLIC_KEY,
	ACTION_SEAL,
	ACTION_UNSEAL,
	ACTION_SIGN
};

enum {
	STOP_EVENT_NONE,
	STOP_EVENT_GRUB_COMMAND,
	STOP_EVENT_GRUB_FILE,
};

struct predictor {
	uint32_t		pcr_mask;
	const char *		initial_source;

	const char *		tpm_event_log_path;

	const char *		algo;
	const tpm_algo_info_t *	algo_info;

	tpm_event_t *		event_log;
	struct {
		int		type;
		bool		after;
		char *		value;
	} stop_event;

	void			(*report_fn)(struct predictor *, unsigned int);

	tpm_pcr_bank_t		prediction;
};

#define GRUB_PCR_SNAPSHOT_PATH	"/sys/firmware/efi/efivars/GrubPcrSnapshot-7ce323f2-b841-4d30-a0e9-5474a76c9a3f"

enum {
	OPT_FROM = 256,
	OPT_USE_PESIGN,
	OPT_STOP_EVENT,
	OPT_AFTER,
	OPT_BEFORE,
	OPT_VERIFY,
	OPT_CREATE_TESTCASE,
	OPT_REPLAY_TESTCASE,
	OPT_TPM_EVENTLOG,
	OPT_RSA_PRIVATE_KEY,
	OPT_RSA_PUBLIC_KEY,
	OPT_INPUT,
	OPT_OUTPUT,
	OPT_AUTHORIZED_POLICY,
	OPT_PCR_POLICY,
};

static struct option options[] = {
	{ "from",		required_argument,	0,	OPT_FROM },
	{ "from-zero",		no_argument,		0,	'Z' },
	{ "from-current",	no_argument,		0,	'C' },
	{ "from-snapshot",	no_argument,		0,	'S' },
	{ "from-eventlog",	no_argument,		0,	'L' },
	{ "algorithm",		required_argument,	0,	'A' },
	{ "format",		required_argument,	0,	'F' },
	{ "stop-event",		required_argument,	0,	OPT_STOP_EVENT },
	{ "tpm-eventlog",	required_argument,	0,	OPT_TPM_EVENTLOG },
	{ "after",		no_argument,		0,	OPT_AFTER },
	{ "before",		no_argument,		0,	OPT_BEFORE },
	{ "verify",		required_argument,	0,	OPT_VERIFY },
	{ "use-pesign",		no_argument,		0,	OPT_USE_PESIGN },
	{ "create-testcase",	required_argument,	0,	OPT_CREATE_TESTCASE },
	{ "replay-testcase",	required_argument,	0,	OPT_REPLAY_TESTCASE },

	{ "private-key",	required_argument,	0,	OPT_RSA_PRIVATE_KEY },
	{ "public-key",		required_argument,	0,	OPT_RSA_PUBLIC_KEY },
	{ "input",		required_argument,	0,	OPT_INPUT },
	{ "output",		required_argument,	0,	OPT_OUTPUT },
	{ "authorized-policy",	required_argument,	0,	OPT_AUTHORIZED_POLICY },
	{ "pcr-policy",		required_argument,	0,	OPT_PCR_POLICY },

	{ NULL }
};

unsigned int opt_debug	= 0;
unsigned int opt_use_pesign = 0;

static void	predictor_report_plain(struct predictor *pred, unsigned int pcr_index);
static void	predictor_report_tpm2_tools(struct predictor *pred, unsigned int pcr_index);
static void	predictor_report_binary(struct predictor *pred, unsigned int pcr_index);

static void
usage(int exitval, const char *msg)
{
	if (msg)
		fputs(msg, stderr);

	fprintf(stderr,
		"\nUsage:\n"
		"pcr-oracle [options] pcr-index [updates...]\n"
		"\n"
		"The following options are recognized:\n"
		"  --from SOURCE          Initialize PCR predictor from indicated source (see below)\n"
		"  -A name, --algorithm name\n"
		"                         Use hash algorithm <name>. Defaults to sha256\n"
		"  -F name, --output-format name\n"
		"                         Specify how to display the resulting PCR values. The default is \"plain\",\n"
		"                         which just prints the value as a hex string. When using \"tpm2-tools\", the\n"
		"                         output string is formatted to resemble the output of tpm2_pcrread.\n"
		"                         Finally, \"binary\" writes our the raw binary data so that it can be consumed\n"
		"                         tpm2_policypcr.\n"
		"  --stop-event TYPE=ARG\n"
		"                         During eventlog based prediction, stop processing the event log at the indicated\n"
		"                         event. Event TYPE can be one of grub-command, grub-file.\n"
		"                         The meaning of event ARG depends on the type. Possible examples are\n"
		"                         grub-command=cryptomount or grub-file=grub.cfg\n"
		"  --after, --before\n"
		"                         The default behavior when using --stop-event is to stop processing the\n"
		"                         event log before the indicated event. Using the --after option instructs\n"
		"                         pcr-oracle to stop after processing the event.\n"
		"  --verify SOURCE        After applying all updates, compare the prediction against the given SOURCE (see below).\n"
		"  --tpm-eventlog PATH\n"
		"                         Specify a different TPM event log to process.\n"
		"\n"
		"The pcr-index argument can be one or more PCR indices or index ranges, separated by comma.\n"
		"Using \"all\" selects all applicable PCR registers.\n"
		"\n"
		"Valid PCR sources for the --from and --verify options include:\n"
                "  zero                   Initialize PCR state to all zero\n"
                "  current                Set the PCR state to the current state of the host's PCR\n"
                "  snapshot               Read the PCR state from a snapshot taken during boot (GrubPcrSnapshot EFI variable)\n"
                "  eventlog               Predict the PCR state using the event log, by substituting current values. Only valid\n"
                "                         as argument to --from.\n"
		"\n"
		"The PCR index can be followed by zero or more pairs of data describing how to extend the PCR.\n"
		"Each pair is a type, and and argument. These types are currently recognized:\n"
		"  string                 The PCR is extended with the string argument.\n"
		"  file                   The argument is taken as a file name. The PCR is extended with the file's content.\n"
		"  eventlog               Process the eventlog and apply updates for all events possible.\n"
		"\n"
		"After the PCR predictor has been extended with all updates specified, its value is printed to standard output.\n"
	       );
	exit(exitval);
}

static void
pcr_bank_load_initial_values(tpm_pcr_bank_t *bank, unsigned int pcr_mask, const tpm_algo_info_t *algo_info, const char *source)
{
	pcr_bank_initialize(bank, pcr_mask, algo_info);
	if (!strcmp(source, "zero")
	 || !strcmp(source, "eventlog"))
		pcr_bank_init_from_zero(bank);
	else if (!strcmp(source, "current"))
		pcr_bank_init_from_current(bank);
	else if (!strcmp(source, "snapshot"))
		pcr_bank_init_from_snapshot(bank, GRUB_PCR_SNAPSHOT_PATH);
	else
		fatal("don't know how to load PCR bank with initial values: unsupported source \"%s\"\n", source);
}

static inline tpm_evdigest_t *
predictor_get_pcr_state(struct predictor *pred, unsigned int index, const char *algo)
{
	return pcr_bank_get_register(&pred->prediction, index, algo);
}

static void
predictor_load_eventlog(struct predictor *pred)
{
	tpm_event_log_reader_t *log;
	tpm_event_t *ev, **tail;
	uint8_t pcr0_locality;

	log = event_log_open(pred->tpm_event_log_path);
	if (log == NULL)
		fatal("Failed to open TPM event log, giving up.\n");

	tail = &pred->event_log;
	while ((ev = event_log_read_next(log)) != NULL) {
		*tail = ev;
		tail = &ev->next;
	}

	if (event_log_get_locality(log, 0, &pcr0_locality))
		pcr_bank_set_locality(&pred->prediction, 0, pcr0_locality);

	/* We check the TPM version after processing the log. Version info for TPMv2
	 * is usually hidden in the first event. */
	if (event_log_get_tpm_version(log) != 2) {
		warning("Encountered TPM event log apparently generated by a TPMv%u device\n",
				event_log_get_tpm_version(log));
		warning("Things will most likely fail\n");
	}

	debug("Successfully read %u events from TPM event log\n", event_log_get_event_count(log));
	event_log_close(log);
}

static struct predictor *
predictor_new(const tpm_pcr_selection_t *pcr_selection, const char *source,
		const char *tpm_eventlog_path,
		const char *output_format)
{
	struct predictor *pred;

	if (source == NULL)
		source = "zero";

	pred = calloc(1, sizeof(*pred));
	pred->pcr_mask = pcr_selection->pcr_mask;
	pred->initial_source = source;

	pred->algo = pcr_selection->algo_info->openssl_name;
	pred->algo_info = pcr_selection->algo_info;

	if (!output_format || !strcasecmp(output_format, "plain"))
		pred->report_fn = predictor_report_plain;
	else
	if (!strcasecmp(output_format, "tpm2-tools"))
		pred->report_fn = predictor_report_tpm2_tools;
	else
	if (!strcasecmp(output_format, "binary"))
		pred->report_fn = predictor_report_binary;
	else
		fatal("Unsupported output format \"%s\"\n", output_format);

	debug("Initializing predictor for %s:%s from %s\n", pred->algo, print_pcr_mask(pred->pcr_mask), source);
	pcr_bank_load_initial_values(&pred->prediction,
			pcr_selection->pcr_mask,
			pcr_selection->algo_info,
			source);

	if (!strcmp(source, "eventlog")) {
		pred->tpm_event_log_path = tpm_eventlog_path;
		predictor_load_eventlog(pred);
	}

	debug("Created new predictor\n");
	return pred;
}

static bool
__stop_event_parse(char *event_spec, char **name_p, char **value_p)
{
	char *s;

	if (!(s = strchr(event_spec, '='))) {
		*name_p = event_spec;
		*value_p = NULL;
		return true;
	}

	*s++ = '\0';
	if (*event_spec == '\0')
		return false;

	*name_p = event_spec;
	*value_p = s;
	return true;
}

static void
predictor_set_stop_event(struct predictor *pred, const char *event_desc, bool after)
{
	char *copy, *name, *value;

	copy = strdup(event_desc);
	if (!__stop_event_parse(copy, &name, &value))
		fatal("Cannot parse stop event \"%s\"\n", event_desc);

	if (!strcmp(name, "grub-command")) {
		pred->stop_event.type = STOP_EVENT_GRUB_COMMAND;
	} else
	if (!strcmp(name, "grub-file")) {
		pred->stop_event.type = STOP_EVENT_GRUB_FILE;
	} else {
		fatal("Unsupported event type \"%s\" in stop event \"%s\"\n", name, event_desc);
	}

	pred->stop_event.value = strdup(value);
	pred->stop_event.after = after;
	free(copy);
}

static void
pcr_bank_extend_register(tpm_pcr_bank_t *bank, unsigned int pcr_index, const tpm_evdigest_t *d)
{
	tpm_evdigest_t *pcr;
	digest_ctx_t *dctx;

	if (!pcr_bank_register_is_valid(bank, pcr_index)) {
		error("Unable to extend PCR %s:%u: register was not initialized\n",
				bank->algo_name, pcr_index);
		return;
	}

	pcr = &bank->pcr[pcr_index];
	if (pcr->algo != d->algo)
		fatal("Cannot update PCR %u: algorithm mismatch\n", pcr_index);

	dctx = digest_ctx_new(pcr->algo);
	digest_ctx_update(dctx, pcr->data, pcr->size);
	digest_ctx_update(dctx, d->data, d->size);
	digest_ctx_final(dctx, pcr);
	digest_ctx_free(dctx);
}

static void
predictor_extend_hash(struct predictor *pred, unsigned int pcr_index, const tpm_evdigest_t *d)
{
	pcr_bank_extend_register(&pred->prediction, pcr_index, d);
}

static const tpm_evdigest_t *
predictor_compute_digest(struct predictor *pred, const void *data, unsigned int size)
{
	return digest_compute(pred->algo_info, data, size);
}

static const tpm_evdigest_t *
predictor_compute_file_digest(struct predictor *pred, const char *filename, int flags)
{
	const tpm_evdigest_t *md;
	buffer_t *buffer;

	buffer = runtime_read_file(filename, flags);

	md = predictor_compute_digest(pred,
			buffer_read_pointer(buffer),
			buffer_available(buffer));
	buffer_free(buffer);

	return md;
}

static void
predictor_update_string(struct predictor *pred, unsigned int pcr_index, const char *value)
{
	const tpm_evdigest_t *md;

	debug("Extending PCR %u with string \"%s\"\n", pcr_index, value);
	md = predictor_compute_digest(pred, value, strlen(value));
	predictor_extend_hash(pred, pcr_index, md);
}

static void
predictor_update_file(struct predictor *pred, unsigned int pcr_index, const char *filename)
{
	const tpm_evdigest_t *md;

	md = predictor_compute_file_digest(pred, filename, 0);
	predictor_extend_hash(pred, pcr_index, md);
}

static bool
__check_stop_event(tpm_event_t *ev, int type, const char *value, tpm_event_log_scan_ctx_t *ctx)
{
	const char *grub_arg = NULL;
	tpm_parsed_event_t *parsed;

	switch (type) {
	case STOP_EVENT_NONE:
		return false;

	case STOP_EVENT_GRUB_COMMAND:
		if (ev->pcr_index != 8
		 || ev->event_type != TPM2_EVENT_IPL)
			return false;

		if (!(parsed = tpm_event_parse(ev, ctx)))
			return false;

		if (parsed->event_subtype != GRUB_EVENT_COMMAND)
			return false;

		if (!(grub_arg = parsed->grub_command.argv[0]))
			return false;

		return !strcmp(grub_arg, value);

	case STOP_EVENT_GRUB_FILE:
		if (ev->pcr_index != 9
		 || ev->event_type != TPM2_EVENT_IPL)
			return false;

		if (!(parsed = tpm_event_parse(ev, ctx)))
			return false;

		if (parsed->event_subtype != GRUB_EVENT_FILE)
			return false;

		if (!(grub_arg = parsed->grub_file.path)) {
			return false;
		} else {
			unsigned int match_len = strlen(value);
			unsigned int path_len = strlen(grub_arg);

			if (path_len > match_len
			 && grub_arg[path_len - match_len - 1] == '/'
			 && !strcmp(value, grub_arg + path_len - match_len)) {
				debug("grub file path \"%s\" matched \"%s\"\n",
						grub_arg, value);
				return true;
			}
		}

		return !strcmp(grub_arg, value);
	}

	return false;
}

/*
 * Scan ahead to a future event that will help us understand the current one.
 */

/*
 * Lookahead: when processing the GPT event, we need to know which hard disk
 * we're talking about.
 */
static void
__predictor_lookahead_efi_partition(tpm_event_t *ev, tpm_event_log_rehash_ctx_t *ctx)
{
	struct efi_gpt_event *gpt = &ev->__parsed->efi_gpt_event;

	while ((ev = ev->next) != NULL) {
		tpm_parsed_event_t *parsed;

		if (ev->event_type != TPM2_EFI_BOOT_SERVICES_APPLICATION)
			continue;

		/* BSA events have already been parsed during the pre-scan */
		if (!(parsed = ev->__parsed))
			continue;

		assign_string(&gpt->efi_partition, parsed->efi_bsa_event.efi_partition);
		return;
	}
}

/*
 * Lookahead: when processing the BSA event that loads the shim loader, scan ahead
 * to the next BSA event (which is probably grub getting loaded).
 * We need this in order to process the "Shim" pseudo variable event that the
 * shim loader produces when verifying the authenticode signature.
 */
static void
__predictor_lookahead_shim_loaded(tpm_event_t *ev, tpm_event_log_rehash_ctx_t *ctx)
{
	tpm_parsed_event_t *parsed;

	while ((ev = ev->next) != NULL) {
		if (ev->event_type != TPM2_EFI_BOOT_SERVICES_APPLICATION)
			continue;

		/* BSA events have already been parsed during the pre-scan */
		if (!(parsed = ev->__parsed))
			continue;

		if (!parsed->efi_bsa_event.img_info)
			continue;

		debug("Inspecting EFI application %s(%s)\n",
				parsed->efi_bsa_event.efi_partition,
				parsed->efi_bsa_event.efi_application);
		ctx->next_stage_img = parsed->efi_bsa_event.img_info;

#ifdef TESTING_ONLY
		if (ctx->next_stage_img) {
			parsed_cert_t *signer;
			buffer_t *record;

			signer = efi_application_extract_signer(parsed);
			if (signer != NULL) {
				debug("Application was signed by %s\n", parsed_cert_subject(signer));
				record = efi_application_locate_authority_record("shim-vendor-cert", signer);
				buffer_free(record);
			}
		}
#endif

		return;
	}
}

static bool
int_list_contains(const int *list, unsigned int value)
{
	while (*list != -1) {
		if (*list++ == value)
			return true;
	}
	return false;
}

static int
predictor_get_event_strategy(unsigned int event_type)
{
	static int rehash_types[] = {
		TPM2_EFI_BOOT_SERVICES_APPLICATION,
		TPM2_EFI_BOOT_SERVICES_DRIVER,
		TPM2_EFI_VARIABLE_BOOT,
		TPM2_EFI_VARIABLE_AUTHORITY,
		TPM2_EFI_VARIABLE_DRIVER_CONFIG,

		/* IPL: used by grub2 for PCR 8 and PCR9 */
		TPM2_EVENT_IPL,

		/*
		 * EFI_GPT_EVENT: used in updates of PCR5, seems to be a hash of several GPT headers.
		 *	We should probably rebuild in case someone changed the partitioning.
		 *	However, not needed as long as we don't seal against PCR5.
		 */
		TPM2_EFI_GPT_EVENT,

		-1,
	};
	static int copy_types[] = {
		TPM2_EVENT_S_CRTM_CONTENTS,
		TPM2_EVENT_S_CRTM_VERSION,
		TPM2_EFI_PLATFORM_FIRMWARE_BLOB,
		TPM2_EFI_PLATFORM_FIRMWARE_BLOB2,
		TPM2_EVENT_SEPARATOR,
		TPM2_EVENT_POST_CODE,
		TPM2_EFI_HANDOFF_TABLES,
		TPM2_EFI_HANDOFF_TABLES2,
		TPM2_EFI_ACTION,
		TPM2_EVENT_ACTION,
		TPM2_EVENT_NONHOST_CODE,
		TPM2_EVENT_NONHOST_CONFIG,
		TPM2_EVENT_NONHOST_INFO,
		TPM2_EVENT_PLATFORM_CONFIG_FLAGS,

		-1
	};

	if (event_type == TPM2_EVENT_NO_ACTION)
		return EVENT_STRATEGY_NO_ACTION;

	if (int_list_contains(rehash_types, event_type))
		return EVENT_STRATEGY_PARSE_REHASH;
	if (int_list_contains(copy_types, event_type))
		return EVENT_STRATEGY_COPY;

	return EVENT_STRATEGY_PARSE_NONE;
}

/*
 * During the pre-scan, we propagate EFI partition information from one BSA event
 * to the next.
 */
static void
predictor_pre_scan_eventlog(struct predictor *pred, tpm_event_t **stop_event_p)
{
	tpm_event_log_scan_ctx_t scan_ctx;
	tpm_event_t *ev;

	*stop_event_p = NULL;

	tpm_event_log_scan_ctx_init(&scan_ctx);
	for (ev = pred->event_log; ev; ev = ev->next) {
		ev->rehash_strategy = predictor_get_event_strategy(ev->event_type);
		/* debug("%s -> %d\n", tpm_event_type_to_string(ev->event_type), ev->rehash_strategy); */

		if (ev->rehash_strategy == EVENT_STRATEGY_PARSE_REHASH) {
			if (!tpm_event_parse(ev, &scan_ctx)) {
				/* Provide better error logging */
				error("Unable to parse %s event from TPM log\n", tpm_event_type_to_string(ev->event_type));
				if (opt_debug)
					__tpm_event_print(ev, debug);
				fatal("Aborting.\n");
			}
		}

		if (__check_stop_event(ev, pred->stop_event.type, pred->stop_event.value, &scan_ctx)) {
			*stop_event_p = ev;
			break;
		}
	}
	tpm_event_log_scan_ctx_destroy(&scan_ctx);
}

static void
predictor_update_eventlog(struct predictor *pred)
{
	tpm_event_log_rehash_ctx_t rehash_ctx;
	tpm_event_t *ev, *stop_event = NULL;

	predictor_pre_scan_eventlog(pred, &stop_event);

	tpm_event_log_rehash_ctx_init(&rehash_ctx, pred->algo_info);
	rehash_ctx.use_pesign = opt_use_pesign;

	for (ev = pred->event_log; ev; ev = ev->next) {
		tpm_evdigest_t *pcr;
		bool stop = false;

		stop = (ev == stop_event);
		if (stop && !pred->stop_event.after) {
			debug("Stopped processing event log before indicated event\n");
			break;
		}

		pcr = predictor_get_pcr_state(pred, ev->pcr_index, NULL);
		if (pcr != NULL) {
			tpm_parsed_event_t *parsed;
			const tpm_evdigest_t *old_digest, *new_digest;
			const char *description = NULL;

			debug("\n");
			__tpm_event_print(ev, debug);

			if (!(old_digest = tpm_event_get_digest(ev, pred->algo)))
				fatal("Event log lacks a hash for digest algorithm %s\n", pred->algo);

			if (false) {
				const tpm_evdigest_t *tmp_digest;

				tmp_digest = digest_compute(pred->algo_info, ev->event_data, ev->event_size);
				if (!tmp_digest) {
					debug("cannot compute digest for event data\n");
				} else if (!digest_equal(old_digest, tmp_digest)) {
					debug("firmware did more than just hash the event data\n");
					debug("  Old digest: %s\n", digest_print(old_digest));
					debug("  New digest: %s\n", digest_print(tmp_digest));
				}
			}

			/* By the time we encounter the GPT event, we usually haven't seen any
			 * BOOT_SERVICES event that would tell us which partition we're booting
			 * from.
			 * Scan ahead to the first BSA event to extract the EFI partition.
			 */
			if (ev->event_type == TPM2_EFI_GPT_EVENT)
				__predictor_lookahead_efi_partition(ev, &rehash_ctx);

			/* The shim loader emits an event that tells us which certificate it
			 * used to verify the second stage loader. We try to predict that
			 * by checking the second stage loader's authenticode sig.
			 */
			if (ev->event_type == TPM2_EFI_BOOT_SERVICES_APPLICATION)
				__predictor_lookahead_shim_loaded(ev, &rehash_ctx);

			switch (ev->rehash_strategy) {
			case EVENT_STRATEGY_PARSE_REHASH:
				/* Event already parsed in pre-scan */
				parsed = ev->__parsed;

				new_digest = tpm_parsed_event_rehash(ev, parsed, &rehash_ctx);
				description = tpm_parsed_event_describe(parsed);
				break;

			case EVENT_STRATEGY_COPY:
				new_digest = old_digest;
				break;

			case EVENT_STRATEGY_NO_ACTION:
				goto no_action;

			default:
				debug("Encountered unexpected event type %s\n",
						tpm_event_type_to_string(ev->event_type));
				new_digest = old_digest;
			}

			if (new_digest == NULL)
				fatal("Cannot re-hash PCR for event type %s\n",
						tpm_event_type_to_string(ev->event_type));

			if (opt_debug && new_digest != old_digest) {
				if (new_digest->size == old_digest->size
				 && !memcmp(new_digest->data, old_digest->data, old_digest->size)) {
					debug("Digest for %s did not change\n", description);
				} else {
					debug("Digest for %s changed\n", description);
					debug("  Old digest: %s\n", digest_print(old_digest));
					debug("  New digest: %s\n", digest_print(new_digest));
				}
			}

			predictor_extend_hash(pred, ev->pcr_index, new_digest);
		}

no_action:
		if (stop) {
			debug("Stopped processing event log after indicated event\n");
			break;
		}
	}

	tpm_event_log_rehash_ctx_destroy(&rehash_ctx);
}

static const char *
get_next_arg(int *index_p, int argc, char **argv)
{
	int i = *index_p;

	if (i >= argc)
		usage(1, "Missing argument\n");
	*index_p += 1;
	return argv[i];
}

static void
predictor_update_all(struct predictor *pred, int argc, char **argv)
{
	int i = 0, pcr_index = -1;

	if (!strcmp(pred->initial_source, "eventlog"))
		predictor_update_eventlog(pred);

	/* If the mask contains exactly one PCR, default pcr_index to that */
	if (!(pred->pcr_mask & (pred->pcr_mask - 1))) {
		unsigned int mask = pred->pcr_mask;

		/* integer log2 */
		for (pcr_index = 0; !(mask & 1); pcr_index++)
			mask >>= 1;
	}

	while (i < argc) {
		const char *type, *arg;

		type = get_next_arg(&i, argc, argv);
		if (isdigit(*type)) {
			if (!parse_pcr_index(type, (unsigned int *) &pcr_index))
				fatal("unable to parse PCR index \"%s\"\n", type);
			type = get_next_arg(&i, argc, argv);
		}

		if (!strcmp(type, "eventlog")) {
			/* do the event log dance */
			continue;
		}

		arg = get_next_arg(&i, argc, argv);
		if (pcr_index < 0) {
			fprintf(stderr, "Unable to infer which PCR to update for %s %s\n", type, arg);
			usage(1, NULL);
		}

		if (!strcmp(type, "string")) {
			predictor_update_string(pred, pcr_index, arg);
		} else
		if (!strcmp(type, "file")) {
			predictor_update_file(pred, pcr_index, arg);
		} else {
			fprintf(stderr, "Unsupported keyword \"%s\" while trying to update predictor\n", type);
			usage(1, NULL);
		}
	}
}

static unsigned int
predictor_verify(struct predictor *pred, const char *source)
{
	tpm_pcr_bank_t actual;
	unsigned int pcr_index;
	unsigned int num_mismatches = 0;

	printf("Verifying predicted state versus \"%s\"\n", source);
	pcr_bank_load_initial_values(&actual, pred->pcr_mask, pred->algo_info, source);

	/* Now compare the digests */
	for (pcr_index = 0; pcr_index < PCR_BANK_REGISTER_MAX; ++pcr_index) {
		tpm_evdigest_t *md_predicted, *md_actual;

		md_predicted = pcr_bank_get_register(&pred->prediction, pcr_index, NULL);
		if (md_predicted == NULL)
			continue;

		if (!pcr_bank_register_is_valid(&actual, pcr_index)) {
			md_actual = NULL;
		} else {
			md_actual = pcr_bank_get_register(&actual, pcr_index, NULL);
		}

		if (md_actual == NULL) {
			/* quietly skip any PCRs we never extended.
			 * This happens when the PCR mask was "all" */
			if (digest_is_zero(md_predicted))
				continue;

			debug("PCR %u not present in %s\n", pcr_index, source);
			printf("%s:%u %s MISSING\n", pred->algo, pcr_index, digest_print_value(md_predicted));
			num_mismatches += 1;
			continue;
		}

		if (digest_equal(md_predicted, md_actual)) {
			printf("%s:%u %s OK\n", pred->algo, pcr_index, digest_print_value(md_predicted));
		} else {
			printf("%s:%u %s MISMATCH", pred->algo, pcr_index, digest_print_value(md_predicted));
			printf("; actual=%s\n", digest_print_value(md_actual));
			num_mismatches += 1;
		}
	}

	if (num_mismatches)
		error("Found %u mismatches\n", num_mismatches);
	return num_mismatches;
}

static void
predictor_report(struct predictor *pred)
{
	const tpm_pcr_bank_t *bank = &pred->prediction;
	unsigned int pcr_index;

	for (pcr_index = 0; pcr_index < PCR_BANK_REGISTER_MAX; ++pcr_index) {
		if (pcr_bank_register_is_valid(bank, pcr_index))
			pred->report_fn(pred, pcr_index);
	}
}

static void
predictor_report_plain(struct predictor *pred, unsigned int pcr_index)
{
	unsigned int i;
	tpm_evdigest_t *pcr;

	if (!(pcr = predictor_get_pcr_state(pred, pcr_index, NULL)))
		return;

	printf("%s:%u ", pred->algo, pcr_index);
	for (i = 0; i < pcr->size; i++)
		printf("%02x", pcr->data[i]);
	printf("\n");
}

static void
predictor_report_tpm2_tools(struct predictor *pred, unsigned int pcr_index)
{
	unsigned int i;
	tpm_evdigest_t *pcr;

	if (!(pcr = predictor_get_pcr_state(pred, pcr_index, NULL)))
		return;

	printf("  %-2d: 0x", pcr_index);
	for (i = 0; i < pcr->size; i++)
		printf("%02X", pcr->data[i]);
	printf("\n");
}

static void
predictor_report_binary(struct predictor *pred, unsigned int pcr_index)
{
	tpm_evdigest_t *pcr;

	if (!(pcr = predictor_get_pcr_state(pred, pcr_index, NULL)))
		return;
	if (fwrite(pcr->data, pcr->size, 1, stdout) != 1)
		fatal("failed to write hash to stdout");
}

static const char *
next_argument(int argc, char **argv)
{
	if (optind >= argc)
		usage(1, "Missing argument(s)");
	return argv[optind++];
}

static void
end_arguments(int argc, char **argv)
{
	if (optind < argc)
		usage(1, "Excess argument(s)");
}

static int
get_action_argument(int argc, char **argv)
{
	static struct act {
		const char *	name;
		int		value;
	} actions[] = {
		{ "predict",			ACTION_PREDICT	},
		{ "create-authorized-policy",	ACTION_CREATE_AUTH_POLICY	},
		{ "store-public-key",		ACTION_STORE_PUBLIC_KEY	 },
		{ "seal-secret",		ACTION_SEAL	},
		{ "unseal-secret",		ACTION_UNSEAL	},
		{ "sign",			ACTION_SIGN	},

		{ NULL, 0 },
	};
	unsigned int i;
	const char *word;

	word = next_argument(argc, argv);

	for (i = 0; actions[i].name; ++i) {
		if (!strcmp(actions[i].name, word))
			return actions[i].value;
	}

	/* Backward compat: predict and display */
	if (pcr_selection_valid_string(word)) {
		optind -= 1;
		return ACTION_PREDICT;
	}

	error("Unknown action \"%s\"\n", word);
	usage(1, NULL);
	return ACTION_NONE;
}

static tpm_pcr_selection_t *
get_pcr_selection_argument(int argc, char ** argv, const char *algo_name)
{
	tpm_pcr_selection_t *pcr_selection;
	const char *word;

	word = next_argument(argc, argv);
	if ((pcr_selection = pcr_selection_new(algo_name, word)) == NULL)
		usage(1, NULL);

	if ((pcr_selection->pcr_mask & (1 << 10)) && ima_is_active()) {
		infomsg("Excluding PCR 10 from prediction (used by IMA)\n");
		pcr_selection->pcr_mask &= ~(1 << 10);
	}

	return pcr_selection;
}

int
main(int argc, char **argv)
{
	struct predictor *pred;
	int action = ACTION_NONE;
	tpm_pcr_selection_t *pcr_selection;
	char *opt_from = NULL;
	char *opt_algo = NULL;
	char *opt_output_format = NULL;
	char *opt_stop_event = NULL;
	char *opt_eventlog_path = NULL;
	bool opt_stop_before = true;
	char *opt_verify = NULL;
	char *opt_create_testcase = NULL;
	char *opt_replay_testcase = NULL;
	char *opt_input = NULL;
	char *opt_output = NULL;
	char *opt_authorized_policy = NULL;
	char *opt_pcr_policy = NULL;
	char *opt_rsa_private_key = NULL;
	char *opt_rsa_public_key = NULL;
	int c, exit_code = 0;

	while ((c = getopt_long(argc, argv, "dhA:CF:LSZ", options, NULL)) != EOF) {
		switch (c) {
		case 'A':
			opt_algo = optarg;
			break;
		case 'F':
			opt_output_format = optarg;
			break;
		case OPT_FROM:
			opt_from = optarg;
			break;
		case 'Z':
			opt_from = "zero";
			break;
		case 'C':
			opt_from = "current";
			break;
		case 'S':
			opt_from = "snapshot";
			break;
		case 'L':
			opt_from = "eventlog";
			break;
		case 'd':
			opt_debug += 1;
			break;
		case OPT_USE_PESIGN:
			opt_use_pesign = 1;
			break;
		case OPT_STOP_EVENT:
			opt_stop_event = optarg;
			break;
		case OPT_TPM_EVENTLOG:
			opt_eventlog_path = optarg;
			break;
		case OPT_AFTER:
			opt_stop_before = false;
			break;
		case OPT_BEFORE:
			opt_stop_before = true;
			break;
		case OPT_VERIFY:
			opt_verify = optarg;
			break;
		case OPT_CREATE_TESTCASE:
			opt_create_testcase = optarg;
			break;
		case OPT_REPLAY_TESTCASE:
			opt_replay_testcase = optarg;
			break;
		case OPT_RSA_PRIVATE_KEY:
			opt_rsa_private_key = optarg;
			break;
		case OPT_RSA_PUBLIC_KEY:
			opt_rsa_public_key = optarg;
			break;
		case OPT_INPUT:
			opt_input = optarg;
			break;
		case OPT_OUTPUT:
			opt_output = optarg;
			break;
		case OPT_AUTHORIZED_POLICY:
			opt_authorized_policy = optarg;
			break;
		case OPT_PCR_POLICY:
			opt_pcr_policy = optarg;
			break;
		case 'h':
			usage(0, NULL);
		default:
			usage(1, "Invalid option");
		}
	}

	action = get_action_argument(argc, argv);

	if (opt_replay_testcase && opt_create_testcase)
		fatal("--create-testcase and --replay-testcase are mutually exclusive\n");

	if (opt_replay_testcase)
		runtime_replay_testcase(testcase_alloc(opt_replay_testcase));

	if (opt_create_testcase)
		runtime_record_testcase(testcase_alloc(opt_create_testcase));

	/* Validate options */
	switch (action) {
	case ACTION_PREDICT:
		pcr_selection = get_pcr_selection_argument(argc, argv, opt_algo);
		end_arguments(argc, argv);
		break;

	case ACTION_STORE_PUBLIC_KEY:
		if (opt_rsa_private_key == NULL)
			usage(1, "You need to specify the RSA secret key using --private-key option\n");
		if (opt_rsa_public_key == NULL)
			opt_rsa_public_key = opt_output;
		end_arguments(argc, argv);
		break;

	case ACTION_CREATE_AUTH_POLICY:
		if (opt_input != NULL)
			warning("Ignoring --input option when creating authorized policy\n");
		if (opt_output != NULL)
			warning("Ignoring --output option when creating authorized policy\n");
		if (opt_rsa_private_key == NULL)
			usage(1, "You need to specify the --private-key option when creating an authorized policy\n");
		pcr_selection = get_pcr_selection_argument(argc, argv, opt_algo);
		end_arguments(argc, argv);
		break;

	case ACTION_SEAL:
		if (opt_authorized_policy == NULL)
			pcr_selection = get_pcr_selection_argument(argc, argv, opt_algo);
		end_arguments(argc, argv);
		break;

	case ACTION_UNSEAL:
		if (opt_authorized_policy) {
			if (opt_rsa_public_key == NULL)
				usage(1, "You need to specify the --public-key option when unsealing using an authorized policy\n");
			if (opt_pcr_policy == NULL)
				usage(1, "You need to specify the --pcr-policy option when unsealing using an authorized policy\n");
			pcr_selection = get_pcr_selection_argument(argc, argv, opt_algo);
		}
		end_arguments(argc, argv);
		break;

	case ACTION_SIGN:
		if (opt_rsa_private_key == NULL)
			usage(1, "You need to specify the --private-key option when signing a policy\n");
		pcr_selection = get_pcr_selection_argument(argc, argv, opt_algo);
		end_arguments(argc, argv);
		break;

	}

	if (action == ACTION_CREATE_AUTH_POLICY) {
		if (!pcr_authorized_policy_create(pcr_selection, opt_rsa_private_key, opt_authorized_policy))
			return 1;

		return 0;
	}

	if (action == ACTION_STORE_PUBLIC_KEY) {
		if (!pcr_store_public_key(opt_rsa_private_key, opt_rsa_public_key))
			return 1;
		return 0;
	}

	/* When sealing a secret against an authorized policy, there's no need to
	 * mess around with PCR values. That's the beauty of it... */
	if (action == ACTION_SEAL && opt_authorized_policy) {
		if (!pcr_authorized_policy_seal_secret(opt_authorized_policy, opt_input, opt_output))
			return 1;

		return 0;
	}

	if (action == ACTION_UNSEAL) {
		if (opt_authorized_policy) {
			/* input is the sealed secret, output is the cleartext */
			if (!pcr_authorized_policy_unseal_secret(pcr_selection, opt_authorized_policy, opt_pcr_policy, opt_rsa_public_key, opt_input, opt_output))
				return 1;
		} else {
			fatal("Unseal using plain PCR policy not implemented\n");
		}

		return 0;
	}

	if (opt_stop_event && (!opt_from || strcmp(opt_from, "eventlog")))
		usage(1, "--stop-event only makes sense when using event log");

	pred = predictor_new(pcr_selection, opt_from, opt_eventlog_path,
			opt_output_format);

	if (opt_stop_event)
		predictor_set_stop_event(pred, opt_stop_event, !opt_stop_before);

	predictor_update_all(pred, argc - optind, argv + optind);

	if (action == ACTION_PREDICT) {
		if (opt_verify)
			exit_code = !!predictor_verify(pred, opt_verify);
		else
			predictor_report(pred);
	} else
	if (action == ACTION_SEAL) {
		/* TBD - seal secret against a set of PCR values */
		fatal("Sealing against a set of PCR values not yet implemented.\n");
	} else
	if (action == ACTION_SIGN) {
		if (!pcr_policy_sign(&pred->prediction, opt_rsa_private_key, opt_output))
			return 1;
	}

	return exit_code;
}
