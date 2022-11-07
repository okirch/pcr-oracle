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

#include <openssl/x509.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "digest.h"
#include "eventlog.h"
#include "runtime.h"
#include "bufparser.h"
#include "util.h"

enum {
	__TPM2_ALG_sha1 = 4,
	__TPM2_ALG_sha256 = 11,
	__TPM2_ALG_sha384 = 12,
	__TPM2_ALG_sha512 = 13,

	TPM2_ALG_MAX
};

#define DESCRIBE_ALGO(name, size) \
	__DESCRIBE_ALGO(name, __TPM2_ALG_ ## name, size)
#define __DESCRIBE_ALGO(name, id, size) \
	[id]	= { id,		#name,		size }
static tpm_algo_info_t		tpm_algorithms[TPM2_ALG_MAX] = {
	DESCRIBE_ALGO(sha1,		20),
	DESCRIBE_ALGO(sha256,		32),
	DESCRIBE_ALGO(sha384,		48),
	DESCRIBE_ALGO(sha512,		64),
};

struct parsed_cert {
	X509 *		x;
};

const tpm_algo_info_t *
__digest_by_tpm_alg(unsigned int algo_id, const tpm_algo_info_t *algorithms, unsigned int num_algoritms)
{
	const tpm_algo_info_t *algo;

	if (algo_id >= num_algoritms)
		return NULL;

	algo = &algorithms[algo_id];
	if (algo->digest_size == 0)
		return NULL;

	return algo;
}

const tpm_algo_info_t *
digest_by_tpm_alg(unsigned int algo_id)
{
	return __digest_by_tpm_alg(algo_id, tpm_algorithms, TPM2_ALG_MAX);
}

const tpm_algo_info_t *
digest_by_name(const char *name)
{
	const tpm_algo_info_t *algo;
	int i;

	for (i = 0, algo = tpm_algorithms; i < TPM2_ALG_MAX; ++i, ++algo) {
		if (algo->openssl_name && !strcasecmp(algo->openssl_name, name))
			return algo;
	}

	return NULL;
}

const char *
digest_algo_name(const tpm_evdigest_t *md)
{
	static char temp[32];
	const char *name;

	if (md->algo == NULL)
		return "unknown";

	if ((name = md->algo->openssl_name) == NULL) {
		snprintf(temp, sizeof(temp), "TPM2_ALG_%u", md->algo->tcg_id);
		name = temp;
	}

	return name;
}

const char *
digest_print(const tpm_evdigest_t *md)
{
	static char buffer[1024];

	snprintf(buffer, sizeof(buffer), "%s: %s",
			digest_algo_name(md),
			digest_print_value(md));
	return buffer;
}

const char *
digest_print_value(const tpm_evdigest_t *md)
{
	static char buffer[2 * sizeof(md->data) + 1];
	unsigned int i;

	assert(md->size <= sizeof(md->data));
        for (i = 0; i < md->size; i++)
                sprintf(buffer + 2 * i, "%02x", md->data[i]);
	return buffer;
}

const tpm_evdigest_t *
digest_compute(const tpm_algo_info_t *algo_info, const void *data, unsigned int size)
{
	static tpm_evdigest_t md;
	digest_ctx_t *ctx;

	memset(&md, 0, sizeof(md));
	ctx = digest_ctx_new(algo_info);
	if (ctx == NULL)
		return NULL;

	digest_ctx_update(ctx, data, size);
	if (!digest_ctx_final(ctx, &md))
		return NULL;

	digest_ctx_free(ctx);
	return &md;
}

const tpm_evdigest_t *
digest_buffer(const tpm_algo_info_t *algo_info, struct buffer *buffer)
{
	return digest_compute(algo_info, buffer_read_pointer(buffer), buffer_available(buffer));
}

const tpm_evdigest_t *
digest_from_file(const tpm_algo_info_t *algo_info, const char *filename, int flags)
{
	const tpm_evdigest_t *md;
	buffer_t *buffer;

	buffer = runtime_read_file(filename, flags);

	md = digest_compute(algo_info,
			buffer_read_pointer(buffer),
			buffer_available(buffer));
	buffer_free(buffer);

	return md;
}


bool
digest_equal(const tpm_evdigest_t *a, const tpm_evdigest_t *b)
{
	return a->algo == b->algo && a->size == b->size && !memcmp(a->data, b->data, a->size);
}

bool
digest_is_zero(const tpm_evdigest_t *md)
{
	unsigned int i;
	unsigned char x = 0;

	for (i = 0; i < md->size; ++i)
		x |= md->data[i];

	return x == 0;
}

bool
digest_is_invalid(const tpm_evdigest_t *md)
{
	unsigned int i;
	unsigned char x = 0xFF;

	for (i = 0; i < md->size; ++i)
		x &= md->data[i];

	return x == 0xFF;
}

struct digest_ctx {
	EVP_MD_CTX *	mdctx;

	tpm_evdigest_t	md;
};

digest_ctx_t *
digest_ctx_new(const tpm_algo_info_t *algo_info)
{
	const EVP_MD *evp_md;
	digest_ctx_t *ctx;

	evp_md = EVP_get_digestbyname(algo_info->openssl_name);
	if (evp_md == NULL) {
		error("Unknown message digest %s\n", algo_info->openssl_name);
		return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	ctx->mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(ctx->mdctx, evp_md, NULL);

	ctx->md.algo = algo_info;

	return ctx;
}

void
digest_ctx_update(digest_ctx_t *ctx, const void *data, unsigned int size)
{
	if (ctx->mdctx == NULL)
		fatal("%s: trying to update digest after having finalized it\n", __func__);

	EVP_DigestUpdate(ctx->mdctx, data, size);
}

tpm_evdigest_t *
digest_ctx_final(digest_ctx_t *ctx, tpm_evdigest_t *result)
{
	tpm_evdigest_t *md = &ctx->md;

	if (ctx->mdctx) {
		EVP_DigestFinal_ex(ctx->mdctx, md->data, &md->size);

		EVP_MD_CTX_free(ctx->mdctx);
		ctx->mdctx = NULL;
	}

	if (result) {
		*result = *md;
		md = result;
	}

	return md;

}

void
digest_ctx_free(digest_ctx_t *ctx)
{
	(void) digest_ctx_final(ctx, NULL);

	free(ctx);
}

/*
 * Information hiding for X509 certs
 */
static parsed_cert_t *
parsed_cert_alloc(X509 *x)
{
	parsed_cert_t *cert;

	cert = calloc(1, sizeof(*cert));
	cert->x = x;
	return cert;
}

void
parsed_cert_free(parsed_cert_t *cert)
{
	X509_free(cert->x);
	free(cert);
}

static const char *
ossl_cert_subject(const X509 *x)
{
	static char namebuf[128];
	X509_NAME *name;

	if (x == NULL)
		return NULL;

	if ((name = X509_get_subject_name(x)) == NULL)
		return NULL;

	return X509_NAME_oneline(name, namebuf, sizeof(namebuf));
}

static const char *
ossl_cert_issuer(const X509 *x)
{
	static char namebuf[128];
	X509_NAME *name;

	if (x == NULL)
		return NULL;

	if ((name = X509_get_issuer_name(x)) == NULL)
		return NULL;

	return X509_NAME_oneline(name, namebuf, sizeof(namebuf));
}

bool
ossl_cert_issued_by(X509 *x, X509 *potential_issuer)
{
	X509_NAME *subject, *issuer;

	if (X509_issuer_name_hash(x) != X509_subject_name_hash(potential_issuer))
		return false;

	if ((issuer = X509_get_issuer_name(x)) == NULL
	 || (subject = X509_get_subject_name(potential_issuer)) == NULL)
		return false;

	if (X509_NAME_cmp(issuer, subject) != 0)
		return false;

	/* FIXME: we may want to make sure this is really the correct cert by
	 * checking the signature. However, we're not doing a real pkcs7 verification
	 * here, we just want to know which cert the shim used to accept the 2nd
	 * stage loader. Right now, this is not very complex so maybe we're fine
	 * with this somewhat simplistic approach. */

	return true;
}

const char *
parsed_cert_subject(const parsed_cert_t *cert)
{
	return ossl_cert_subject(cert->x);
}

const char *
parsed_cert_issuer(const parsed_cert_t *cert)
{
	return ossl_cert_issuer(cert->x);
}

bool
parsed_cert_issued_by(const parsed_cert_t *cert, const parsed_cert_t *potential_issuer)
{
	return ossl_cert_issued_by(cert->x, potential_issuer->x);
}

parsed_cert_t *
cert_parse(const buffer_t *bp)
{
	const unsigned char *rptr = buffer_read_pointer(bp);
	X509 *x = NULL;

	if (!d2i_X509(&x, &rptr, buffer_available(bp)))
		return NULL;
	return parsed_cert_alloc(x);
}

/*
 * PKCS7 stuff. Needed to handle Authenticode code signing certs
 */
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

static inline buffer_t *
x509_as_buffer(X509 *x509)
{
	unsigned char *der = NULL;
	int len;
	buffer_t *bp;

	len = i2d_X509(x509, &der);
	if (len < 0)
		return NULL;

	bp = buffer_alloc_write(len);
	buffer_put(bp, der, len);
	free(der);

	return bp;
}

parsed_cert_t *
pkcs7_extract_signer(buffer_t *data)
{
	parsed_cert_t *result = NULL;
	const unsigned char *raw_data;
	unsigned int raw_len;
	PKCS7 *p7 = NULL;
	STACK_OF(X509) *chain;
	X509 *x509;

	raw_data = buffer_read_pointer(data);
	raw_len = buffer_available(data);

	if (!d2i_PKCS7(&p7, &raw_data, raw_len)) {
		debug("%s: cannot parse blob as PKCS#7\n", __func__);
		return NULL;
	}

	if (!PKCS7_type_is_signed(p7)) {
		debug("%s: blob is a PKCS#7 object, but not a signed thingy\n", __func__);
		goto out;
	}

	chain = p7->d.sign->cert;

	/* empty signing chain */
	if (sk_X509_num(chain) == 0) {
		debug("%s: signing chain contains %d certificates\n", __func__, sk_X509_num(chain));
		goto out;
	}

	if (!(x509 = sk_X509_value(chain, 0))) {
		debug("%s: couldn't get cert 0 from chain\n", __func__);
		goto out;
	}

	result = parsed_cert_alloc(X509_dup(x509));

out:
	if (p7)
		PKCS7_free(p7);
	return result;
}
