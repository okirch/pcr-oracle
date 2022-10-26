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
 * Using FIDO2 to derive a storage secret feels a bit odd. Given that yubikeys
 * also seem to support CCID, maybe there is a more straightforward
 * way to address this.
 *
 * Written by Olaf Kirch <okir@suse.com>
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <fido.h>
#include <fido/credman.h>
#include <fido/err.h>

#define FDE_FIDO2_CHALLENGE		"SUSE FDE CHALLENGE"
#define FDE_FIDO2_RELYING_PARTY		"SUSE FULL DISK ENCRYPTION"
#define FDE_FIDO2_USER_NAME		"Ruth the Ruthless SysAdmin"
#define FDE_FIDO2_USER_ID		"root"

enum {
	OPT_NO_PROMPT,
};

static struct option	options[] = {
	{ "device",	required_argument,	NULL,	'D' },
	{ "output",	required_argument,	NULL,	'o' },
	{ "pin",	required_argument,	NULL,	'P' },
	{ "no-prompt",	no_argument,		NULL,	OPT_NO_PROMPT },
	{ "quiet",	no_argument,		NULL,	'q' },
	{ "debug",	no_argument,		NULL,	'd' },
	{ "help",	no_argument,		NULL,	'h' },

	{ NULL }
};

struct fde_blob {
	unsigned char *		data;
	size_t			len;
};

struct fde_params {
	const char *		device_path;
	bool			allow_prompt;	/* default true */
	int			pin_fd;		/* not used yet */
	char *			pin;
};

struct fde_token {
	struct fde_params	params;

	char *			device_path;
	fido_dev_t *		dev;
	char *			pin;

	const fido_credman_rk_t *rk;
	struct fde_blob		cred_id;
};

#define debug(msg ...) \
	do {					\
		if (opt_debug)			\
			fprintf(stderr, msg);	\
	} while (0)

static void	usage(const char *msg, int exitval);
static void	fatal(const char *fmt, ...);
static void	fde_token_init(struct fde_token *token);
static int	fde_token_discover_devices(struct fde_token *token);
static int	fde_token_check_devices(struct fde_token *token);
static int	fde_token_enroll(struct fde_token *token);
static bool	fde_token_discover_fresh_device(struct fde_token *token);
static bool	fde_token_discover_credential(struct fde_token *token);
static bool	fde_token_get_secret(struct fde_token *token, const char *uuid, struct fde_blob *secret);
static bool	fde_token_write_key(const struct fde_blob *secret, const char *key_file);
static void	fde_blob_clear(struct fde_blob *blob);

static bool	opt_debug = false;
static bool	opt_quiet = false;

int
main(int argc, char **argv)
{
	struct fde_token token;
	char *opt_key_file = NULL;
	const char *verb;
	struct fde_blob secret;
	int c;

	fde_token_init(&token);
	while ((c = getopt_long(argc, argv, "dhqD:o:P:", options, NULL)) != -1) {
		switch (c) {
		case 'D':
			token.params.device_path = optarg;
			break;

		case 'o':
			opt_key_file = optarg;
			break;

		case 'P':
			token.params.pin = optarg;
			break;

		case OPT_NO_PROMPT:
			token.params.allow_prompt = false;
			break;

		case 'h':
			usage(NULL, 0);

		case 'q':
			opt_quiet = true;
			break;

		case 'd':
			opt_debug = true;
			break;

		default:
			usage("bad argument", 2);
		}

	}

	if (optind >= argc)
		usage("Missing argument(s)", 2);
	verb = argv[optind++];

	if (!strcmp(verb, "detect"))
		return fde_token_discover_devices(&token);
	if (!strcmp(verb, "check"))
		return fde_token_check_devices(&token);
	if (!strcmp(verb, "enroll")) {
		if (!fde_token_discover_fresh_device(&token))
			fatal("Failed to discover suitable FIDO2 token\n");
		return fde_token_enroll(&token);
	}

	if (!strcmp(verb, "get-secret")) {
		bool ok;

		if (!fde_token_discover_credential(&token))
			fatal("Failed to discover suitable FIDO2 token\n");

		if (!fde_token_get_secret(&token, argv[optind], &secret))
			return 1;

		ok = fde_token_write_key(&secret, opt_key_file);

		fde_blob_clear(&secret);
		return ok? 0 : 1;
	}

	fprintf(stderr, "Invalid action \"%s\"\n", verb);
	usage(NULL, 2);
}

static void
usage(const char *msg, int exitval)
{
	fprintf(stderr, "%s\n", msg);
	fprintf(stderr,
		"\n"
		"Usage:\n"
		"  fde-token detect\n"
		"        Detect presence of a suitable FIDO2 token\n"
		"  fde-token check\n"
		"        Print token characteristics as a list of IDs.\n"
		"        \"pin\" indicates that a PIN is required.\n"
		"  fde-token enroll\n"
		"        Create FDE credentials on FIDO2 token.\n"
		"  fde-token clear\n"
		"        Remove existing FDE credentials from FIDO2 token.\n"
		"  fde-token get-secret\n"
		"        Derive symmetric key from existing FDE credential.\n"
		"\n"
		"The following options are recognized:\n"
		"  --pin PIN, -p PIN\n"
		"        Supply PIN required to talk to the device\n"
		"  --device PATH, -D PATH\n"
		"        Specify a HID device by path, rather than scanning for one.\n"
		"        When enrollment detects several devices, this is needed to\n"
		"        disambiguate.\n"
		"  --output PATH, -o PATH\n"
		"        With get-secret, specify the path of a file to write the key to.\n"
		"        If no output file is specified, the key is written to standard output.\n"
		"  --debug, -d\n"
		"        Enable debugging messages.\n"
		"  --help, -h\n"
		"        Print this message and exit.\n"
	       );

	exit(exitval);
}

static void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "Fatal: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(2);
}

static void
error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "Error: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

static void
fde_blob_clear(struct fde_blob *blob)
{
	if (blob->data) {
		/* zap contents, they may be confidential */
		memset(blob->data, 0, blob->len);

		free(blob->data);
		blob->data = NULL;
		blob->len = 0;
	}
}

static void
fde_blob_set(struct fde_blob *blob, const void *data, size_t len)
{
	fde_blob_clear(blob);

	blob->data = malloc(len);
	if (blob->data == NULL)
		fatal("%s: failed to allocate buffer of %u bytes\n", __func__, len);

	memcpy(blob->data, data, len);
	blob->len = len;
}

static void
fde_token_init(struct fde_token *token)
{
	memset(token, 0, sizeof(*token));
	token->params.pin_fd = -1;
	token->params.allow_prompt = true;
}

static void
fde_token_clear_pin(struct fde_token *token)
{
	if (token->pin) {
		memset(token->pin, 0, strlen(token->pin));
		free(token->pin);
		token->pin = NULL;
	}
}

static void
fde_token_set_pin(struct fde_token *token, const char *pin)
{
	fde_token_clear_pin(token);
	token->pin = strdup(pin);
	if (token->pin == NULL)
		fatal("%s: failed to allocate memory\n", __func__);
}

static bool
fde_token_attach(struct fde_token *token, const char *dev_path)
{
	if (token->dev == NULL) {
		fido_dev_t *dev;
		int r;

		if ((dev = fido_dev_new()) == NULL)
			fatal("fido_dev_new: out of memory\n");

		r = fido_dev_open(dev, dev_path);
		if (r != FIDO_OK) {
			fido_dev_close(dev);
			fido_dev_free(&dev);
			return false;
		}

		token->device_path = strdup(dev_path);
		token->dev = dev;
	}

	return true;
}

static void
fde_token_detach(struct fde_token *token)
{
	if (token->dev != NULL) {
		fido_dev_close(token->dev);
		fido_dev_free(&token->dev);
	}

	fde_token_clear_pin(token);

	if (token->device_path) {
		free(token->device_path);
		token->device_path = NULL;
	}
}

static bool
fde_maybe_retry_with_pin(struct fde_token *token, int code)
{
	char *pin;

        if (!fido_dev_has_pin(token->dev))
                return false;

	if (token->pin || !token->params.allow_prompt)
                return false;

	/* It would have been nice to check for error codes like
	 * FIDO_ERR_PIN_REQUIRED. Alas, fido_credman_get_dev_rk returns
	 * INVALID_ARGUMENT when called w/o pin. */
	debug("Operation returns error %d (%s) - let's retry with PIN\n", code, fido_strerr(code));

	if (token->params.pin) {
		fde_token_set_pin(token, token->params.pin);
		return true;
	}

	pin = getpass("Please enter PIN for FIDO token: ");
	if (pin == NULL)
		return false;

	fde_token_set_pin(token, pin);
	return true;
}

/*
 * Having attached to a token, check whether it contains credentials
 * for the relying party rp_id.
 * If it does, token->id will be set to the credential ID as a side
 * effect.
 */
static bool
fde_find_credential(struct fde_token *token, const char *rp_id)
{
        fido_credman_rk_t *rk = NULL;
	bool found = false;
        int r;

	debug("%s(\"%s\") called\n", __func__, rp_id);
        if ((rk = fido_credman_rk_new()) == NULL)
		return false;

	/* debug("TP %d\n", __LINE__); */
	do {
		r = fido_credman_get_dev_rk(token->dev, rp_id, rk, token->pin);
	} while (r != FIDO_OK && fde_maybe_retry_with_pin(token, r));

        if (r != FIDO_OK) {
		debug("fido_credman_get_dev_rk() = %s\n", fido_strerr(r));
                goto out;
        }

        for (size_t i = 0; i < fido_credman_rk_count(rk); i++) {
		const fido_cred_t *fcred;

		if ((fcred = fido_credman_rk(rk, i)) != NULL) {
			/* Extract all info from the token that we will need later. */
			fde_blob_set(&token->cred_id, fido_cred_id_ptr(fcred), fido_cred_id_len(fcred));
			found = true;
			break;
		}
	}

out:
	fido_credman_rk_free(&rk);
	return found;
}

/*
 * Enumerate FIDO devices.
 * If the user supplied a --device argument on the command line,
 * check just this device. Otherwise, loop over all available
 * tokens. The first valid one is returned in token->dev.
 */
static bool
fde_token_enumerate_devices(struct fde_token *token,
		bool (*check_fn)(struct fde_token *))
{
	fido_dev_info_t *devlist;
	size_t i, ndevs;
	int r;

	if (token->params.device_path) {
		if (!fde_token_attach(token, token->params.device_path))
			return false;

		if (check_fn && !check_fn(token)) {
			fde_token_detach(token);
			return false;
		}

		return true;
	}

	if ((devlist = fido_dev_info_new(64)) == NULL)
		fatal("fido_dev_info_new failed\n");

	if ((r = fido_dev_info_manifest(devlist, 64, &ndevs)) != FIDO_OK)
		fatal("unable to obtain list of FIDO capable devices: %s\n", fido_strerr(r));

	for (i = 0; i < ndevs; i++) {
		const fido_dev_info_t *dev_info = fido_dev_info_ptr(devlist, i);
		const char *dev_path = fido_dev_info_path(dev_info);

		debug("Checking device %s (%s %s)\n", dev_path,
				fido_dev_info_manufacturer_string(dev_info),
				fido_dev_info_product_string(dev_info));
		if (fde_token_attach(token, dev_path)) {
			if (check_fn == NULL || check_fn(token))
				break;
		}

		fde_token_detach(token);
	}

	fido_dev_info_free(&devlist, ndevs);
	return token->dev != NULL;
}

static bool
__fde_token_has_extension(fido_dev_t *dev, const char *name)
{
	fido_cbor_info_t *ci = NULL;
	unsigned int count, i;
	char * const * list;
	int r;
	bool ok;

	if ((ci = fido_cbor_info_new()) == NULL)
		fatal("%s: cannot allocate CBOR info\n", __func__);

	if ((r = fido_dev_get_cbor_info(dev, ci)) != FIDO_OK) {
		debug("%s: fido_dev_get_cbor_info returns %s\n", __func__, fido_strerr(r));
		goto out;
	}

	list = fido_cbor_info_extensions_ptr(ci);
	count = fido_cbor_info_extensions_len(ci);
	for (i = 0; i < count; ++i) {
		const char *extension = list[i];

		debug("  token has extension %s\n", extension);
		if (!strcmp(extension, name)) {
			ok = true;
			break;
		}
	}

out:
	fido_cbor_info_free(&ci);
	return ok;
}

static bool
__fde_token_check_device(struct fde_token *token)
{
	fido_dev_t *dev = token->dev;

	if (!fido_dev_is_fido2(dev)) {
		debug("%s is not a FIDO2 device\n", token->device_path);
		return false;
	}

	if (!__fde_token_has_extension(dev, "hmac-secret")) {
		debug("%s lacks extension hmac-secret\n", token->device_path);
		return false;
	}

	debug("nice device!\n");
	return true;
}

static int
fde_token_discover_devices(struct fde_token *token)
{
	if (fde_token_enumerate_devices(token, __fde_token_check_device)) {
		if (!opt_quiet)
			printf("%s\n", token->device_path);
		return 0;
	}

	return 1;
}

static int
fde_token_check_devices(struct fde_token *token)
{
	if (fde_token_enumerate_devices(token, __fde_token_check_device)) {
		if (!opt_quiet) {
			fido_dev_t *dev = token->dev;

			printf("%s", token->device_path);
			if (fido_dev_has_pin(dev))
				printf(" pin");
			printf("\n");
		}
		return 0;
	}

	return 1;
}

static bool
__fde_token_check_credential(struct fde_token *token)
{
	if (fde_find_credential(token, FDE_FIDO2_RELYING_PARTY)) {
		debug("Found \"%s\" on %s\n", FDE_FIDO2_RELYING_PARTY, token->device_path);
		return true;
	}

	return false;
}

static bool
fde_token_discover_credential(struct fde_token *token)
{
	return fde_token_enumerate_devices(token, __fde_token_check_credential);
}

/*
 * Discover a FIDO2 token that has no FDE credential yet
 */
static bool
__fde_token_check_fresh(struct fde_token *token)
{
	if (__fde_token_check_credential(token)) {
		debug("%s is already enrolled, not touching it\n", token->device_path);
		return false;
	}

	return __fde_token_check_device(token);
}

static bool
fde_token_discover_fresh_device(struct fde_token *token)
{
	return fde_token_enumerate_devices(token, __fde_token_check_fresh);
}

static int
fde_hash_clientdata(const char *algo, const char *data, size_t len, unsigned char *md_buf, size_t md_size)
{
	const EVP_MD *md;
	EVP_MD_CTX *mdctx;
	unsigned int md_len;

	if (!(md = EVP_get_digestbyname(algo))) {
		error("Unknown hash algorithm \"%s\"\n", algo);
		return -1;
	}

	if (md_size < EVP_MD_size(md)) {
		error("%s: digest buffer too small for hash algo %s\n", __func__, algo);
		return -1;
	}

	mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, md, NULL);
        EVP_DigestUpdate(mdctx, data, len);
        EVP_DigestFinal_ex(mdctx, md_buf, &md_len);
        EVP_MD_CTX_free(mdctx);

	return md_len;
}

/*
 * Create a resident credential on the token
 */
static fido_cred_t *
fde_token_make_credential(struct fde_token *token, const char *challenge, const char *username)
{
	fido_cred_t *cred = NULL;
	unsigned char cdh[128], uh[128];
	int r, cdh_len, uh_len;
	bool allow_up = false;

	if ((cdh_len = fde_hash_clientdata("sha256", challenge, strlen(challenge), cdh, sizeof(cdh))) < 0)
		fatal("unable to hash challenge\n");
	if ((uh_len = fde_hash_clientdata("sha256", username, strlen(username), uh, sizeof(uh))) < 0)
		fatal("unable to hash username\n");

	cred = fido_cred_new();
	if (!cred)
		return NULL;

	r = fido_cred_set_type(cred, COSE_ES256);
	if (r == FIDO_OK)
		r = fido_cred_set_clientdata_hash(cred, cdh, cdh_len);
	if (r == FIDO_OK)
		r = fido_cred_set_rp(cred, FDE_FIDO2_RELYING_PARTY, NULL);
	if (r == FIDO_OK)
		r = fido_cred_set_user(cred, uh, uh_len, username, NULL, NULL);
	if (r == FIDO_OK)
		r = fido_cred_set_rk(cred, FIDO_OPT_TRUE);

	/* fido_cred_set_up(cred, FIDO_OPT_FALSE); */

	if (r != FIDO_OK) {
                error("unable to build FIDO2 credential: %s\n", fido_strerr(r));
		goto out;
	}

	/* For credentials, I haven't discovered a way to detect whether the operation requires user
	 * presence or not. fido_cred_* does not seem to have anything analogous to fido_assert_set_up */

	fprintf(stderr, "The token may require you to confirm user presence. Please watch out for any blinkenlights\n");
	allow_up = true;

	do {
		r = fido_dev_make_cred(token->dev, cred, token->pin);
		if (r == FIDO_ERR_UP_REQUIRED && !allow_up) {
			fprintf(stderr, "FIDO token requires user presence, watch out for any blinkenlights\n");
			/* fido_cred_set_up(cred, FIDO_OPT_TRUE); */
			allow_up = true;

			r = fido_dev_make_cred(token->dev, cred, token->pin);
		}
	} while (r != FIDO_OK && fde_maybe_retry_with_pin(token, r));

	if (r != FIDO_OK) {
		error("Unable to create resident credential on device %s\n", token->device_path);
		goto out;
	}

	return cred;

out:
	fido_cred_free(&cred);
	return NULL;
}

static int
fde_token_enroll(struct fde_token *token)
{
	fido_cred_t *cred;

	cred = fde_token_make_credential(token, FDE_FIDO2_RELYING_PARTY, FDE_FIDO2_USER_NAME);
	if (cred == NULL) {
		error("Unable to create resident credential\n");
		return 1;
	}

	if (!__fde_token_check_credential(token)) {
		error("Strange, I thought I enrolled a credential but now I cannot find it\n");
		return 1;
	}

	return 0;
}

/*
 * Create a FIDO assert for the selected credentials and return it.
 * The sole purpose of doing that is to derive the 32byte key provided by the hmac-secret
 * extension.
 */
static fido_assert_t *
fde_token_make_assert(struct fde_token *token, const char *uuid)
{
	static unsigned char zero_salt[32] = { 0, };
	unsigned char cdh[128];
	fido_assert_t *assert;
	int r, cdh_len;
	bool allow_up = false;

	assert = fido_assert_new();

	if ((cdh_len = fde_hash_clientdata("sha256", uuid, strlen(uuid), cdh, sizeof(cdh))) < 0)
		fatal("unable to hash uuid\n");

	r = fido_assert_set_clientdata_hash(assert, cdh, cdh_len);
	if (r == FIDO_OK)
		r = fido_assert_set_rp(assert, FDE_FIDO2_RELYING_PARTY);
	if (r == FIDO_OK)
		r = fido_assert_allow_cred(assert, token->cred_id.data, token->cred_id.len);
	if (r == FIDO_OK)
		r = fido_assert_set_extensions(assert, FIDO_EXT_HMAC_SECRET);
	if (r == FIDO_OK)
		r = fido_assert_set_hmac_salt(assert, zero_salt, sizeof(zero_salt));

	fido_assert_set_up(assert, FIDO_OPT_FALSE);

	if (r != FIDO_OK) {
		error("Unable to set up assert parameters\n");
		goto out;
	}

	do {
		r = fido_dev_get_assert(token->dev, assert, token->pin);
		if (r == FIDO_ERR_UP_REQUIRED && !allow_up) {
			fprintf(stderr, "FIDO token requires user presence, watch out for any blinkenlights\n");
			fido_assert_set_up(assert, FIDO_OPT_TRUE);
			allow_up = true;

			r = fido_dev_get_assert(token->dev, assert, token->pin);
		}
	} while (r != FIDO_OK && fde_maybe_retry_with_pin(token, r));

	if (r != FIDO_OK) {
		error("Unable to get assert from device %s\n", token->device_path);
		goto out;
	}

	return assert;

out:
	fido_assert_free(&assert);
	return NULL;
}

static bool
fde_token_get_secret(struct fde_token *token, const char *uuid, struct fde_blob *secret)
{
	fido_assert_t *assert;
	assert = fde_token_make_assert(token, uuid);
	if (!assert)
		return false;

	fde_blob_set(secret,
			fido_assert_hmac_secret_ptr(assert, 0),
			fido_assert_hmac_secret_len(assert, 0));

	fido_assert_free(&assert);
	return true;
}

static bool
__fde_token_write_key(const struct fde_blob *secret, FILE *fp)
{
	int r;

	r = fwrite(secret->data, secret->len, 1, fp);
	if (r < 0) {
		error("Failed to write to key file: %m\n");
		return false;
	}

	if (r != 1) {
		error("Short write to key file: %m\n");
		return false;
	}

	debug("Wrote %u key bytes\n", (int) secret->len);
	return true;
}

static bool
fde_token_write_key(const struct fde_blob *secret, const char *key_file)
{
	FILE *fp;
	bool ok;

	if (key_file == NULL)
		return __fde_token_write_key(secret, stdout);

	if (!(fp = fopen(key_file, "w"))) {
		error("Unable to open key file \"%s\": %m\n", key_file);
		return false;
	}

	ok = __fde_token_write_key(secret, fp);
	if (fclose(fp) != 0) {
		error("Failed to write to key file: %m\n");
		return false;
	}

	fprintf(stderr, "Wrote secret key to file %s\n", key_file);
	return ok;
}
