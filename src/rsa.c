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

#include <openssl/pem.h>
#include <tss2_esys.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#include "util.h"
#include "rsa.h"

struct tpm_rsa_key {
	bool		is_private;

	char *		path;
	EVP_PKEY *	pkey;
};

static tpm_rsa_key_t *
tpm_rsa_key_alloc(const char *path, EVP_PKEY *pkey, bool priv)
{
	tpm_rsa_key_t *key;

	key = calloc(1, sizeof(*key));
	key->is_private = priv;
	key->pkey = pkey;
	key->path = strdup(path);
	return key;
}


void
tpm_rsa_key_free(tpm_rsa_key_t *key)
{
	/* TBD */
}

/*
 * Read a public key from a PEM file.
 */
tpm_rsa_key_t *
tpm_rsa_key_read_public(const char *pathname)
{
	EVP_PKEY *pkey = NULL;
	FILE *fp;

	if (!(fp = fopen(pathname, "r"))) {
		error("Cannot read RSA public key from %s: %m\n", pathname);
		goto fail;
	}
	pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);

	if (pkey == NULL) {
		error("Failed to parse RSA public key from %s\n", pathname);
		goto fail;
	}

	if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
		error("Not a RSA public key: %s\n", pathname);
		goto fail;
	}

	return tpm_rsa_key_alloc(pathname, pkey, false);

fail:
	if (pkey)
		EVP_PKEY_free(pkey);
	return NULL;
}

/*
 * Read a private key from a PEM file.
 * Pass phrases currently not supported.
 */
tpm_rsa_key_t *
tpm_rsa_key_read_private(const char *pathname)
{
	EVP_PKEY *pkey = NULL;
	FILE *fp;

	if (!(fp = fopen(pathname, "r"))) {
		error("Cannot read RSA private key from %s: %m\n", pathname);
		goto fail;
	}
	pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
	fclose(fp);

	if (pkey == NULL) {
		error("Failed to parse RSA private key from %s\n", pathname);
		goto fail;
	}

	if (EVP_PKEY_id(pkey) != EVP_PKEY_RSA) {
		error("Not a RSA private key: %s\n", pathname);
		goto fail;
	}

	return tpm_rsa_key_alloc(pathname, pkey, true);

fail:
	if (pkey)
		EVP_PKEY_free(pkey);
	return NULL;
}

int
tpm_rsa_sign(const tpm_rsa_key_t *key,
			const void *tbs_data, size_t tbs_len,
			void *sig_data, size_t sig_size)
{
	EVP_MD_CTX *ctx;

	if (!key->is_private) {
		error("Cannot use %s for signing - not a private key\n", key->path);
		return 0;
	}

	ctx = EVP_MD_CTX_new();

	if (!EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, key->pkey)) {
		error("EVP_DigestSignInit failed\n");
		return 0;
	}

	if (!EVP_DigestSign(ctx,
			(unsigned char *) sig_data, &sig_size,
			(const unsigned char *) tbs_data, tbs_len)) {
		error("EVP_DigestSign failed\n");
		EVP_MD_CTX_free(ctx);
		return 0;
	}

	EVP_MD_CTX_free(ctx);
	return sig_size;
}

/*
 * Convert openssl public key to a structure understood by tss2
 */
static inline TPM2B_PUBLIC *
__rsa_pubkey_alloc(void)
{
	TPM2B_PUBLIC *result;

	result = calloc(1, sizeof(*result));
	result->size = sizeof(result->publicArea);
	result->publicArea.type = TPM2_ALG_RSA;
	result->publicArea.nameAlg = TPM2_ALG_SHA256;
	result->publicArea.objectAttributes = TPMA_OBJECT_DECRYPT | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_USERWITHAUTH;

	TPMS_RSA_PARMS *rsaDetail = &result->publicArea.parameters.rsaDetail;
	rsaDetail->scheme.scheme = TPM2_ALG_NULL;
	rsaDetail->symmetric.algorithm = TPM2_ALG_NULL;
	rsaDetail->scheme.details.anySig.hashAlg = TPM2_ALG_NULL;

	/* NULL out sym details */
	TPMT_SYM_DEF_OBJECT *sym = &rsaDetail->symmetric;
	sym->algorithm = TPM2_ALG_NULL;
	sym->keyBits.sym = 0;
	sym->mode.sym = TPM2_ALG_NULL;

	return result;
}

static inline TPM2B_PUBLIC *
rsa_pubkey_alloc(const BIGNUM *n, const BIGNUM *e, const char *pathname)
{
	TPM2B_PUBLIC *result;
	unsigned int key_bits;

	key_bits = BN_num_bytes(n) * 8;
	if (key_bits != 1024 && key_bits != 2048 && key_bits != 4096) {
		error("%s: unsupported RSA key size (%u bits)\n", pathname, key_bits);
		return NULL;
	}

	if (BN_num_bytes(e) > sizeof(((TPMS_RSA_PARMS *) 0)->exponent)) {
		error("%s: unsupported RSA modulus size (%u bits)\n", pathname, BN_num_bytes(e) * 8);
		return NULL;
	}

	if (!(result = __rsa_pubkey_alloc()))
		return NULL;

	TPMS_RSA_PARMS *rsaDetail = &result->publicArea.parameters.rsaDetail;
	rsaDetail->keyBits = key_bits;

	TPM2B_PUBLIC_KEY_RSA *rsaPublic = &result->publicArea.unique.rsa;
	rsaPublic->size = BN_num_bytes(n);

	if (!BN_bn2bin(n, rsaPublic->buffer))
		goto failed;

	if (!BN_bn2bin(e, (void *) &rsaDetail->exponent))
		goto failed;

	return result;

failed:
	free(result);
	return NULL;
}

TPM2B_PUBLIC *
tpm_rsa_key_to_tss2(const tpm_rsa_key_t *key)
{
#if OPENSSL_VERSION_NUMBER < 0x30000000L
	RSA *rsa;
	const BIGNUM *n, *e;

	if (!(rsa = EVP_PKEY_get0_RSA(key->pkey))) {
		error("%s: cannot extract RSA modulus and exponent - EVP_PKEY_get0_RSA failed\n", key->path);
		return NULL;
	}

	RSA_get0_key(rsa, &n, &e, NULL);
#else
	BIGNUM *n = NULL, *e = NULL;

	if (!EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_N, &n)) {
		error("%s: cannot extract RSA modulus\n", key->path);
		return NULL;
	}
	if (!EVP_PKEY_get_bn_param(key->pkey, OSSL_PKEY_PARAM_RSA_E, &e)) {
		error("%s: cannot extract RSA exponent\n", key->path);
		return NULL;
	}
#endif
	return rsa_pubkey_alloc(n, e, key->path);
}

