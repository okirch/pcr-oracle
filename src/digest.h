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


#ifndef DIGEST_H
#define DIGEST_H

#include <openssl/evp.h>
#include "types.h"

struct tpm_algo_info {
	unsigned int		tcg_id;
	const char *		openssl_name;
	unsigned int		digest_size;
};

struct tpm_evdigest {
	const tpm_algo_info_t *	algo;
	unsigned int		size;
	unsigned char		data[EVP_MAX_MD_SIZE];
};

#define WIN_CERT_TYPE_X509	0x0001
#define WIN_CERT_TYPE_AUTH	0x0002

struct win_cert {
	int			type;
	buffer_t *		blob;
	buffer_t *		signer_cert;
};

#define MAX_CERTIFICATES	8

struct cert_table {
	unsigned int		count;
	win_cert_t *		cert[MAX_CERTIFICATES];
};

extern const tpm_algo_info_t *	digest_by_tpm_alg(unsigned int algo_id);
extern const tpm_algo_info_t *	digest_by_name(const char *name);
extern const char *		digest_print(const tpm_evdigest_t *);
extern const char *		digest_print_value(const tpm_evdigest_t *);
extern const char *		digest_algo_name(const tpm_evdigest_t *);
extern bool			digest_equal(const tpm_evdigest_t *a, const tpm_evdigest_t *b);
extern bool			digest_is_zero(const tpm_evdigest_t *);
extern bool			digest_is_invalid(const tpm_evdigest_t *);
extern void			digest_set(tpm_evdigest_t *, const tpm_algo_info_t *,
					unsigned int size, const void *data);

extern digest_ctx_t *		digest_ctx_new(const tpm_algo_info_t *);
extern void			digest_ctx_update(digest_ctx_t *, const void *, unsigned int);
extern tpm_evdigest_t *		digest_ctx_final(digest_ctx_t *, tpm_evdigest_t *);
extern void			digest_ctx_free(digest_ctx_t *);
extern const tpm_evdigest_t *	digest_buffer(const tpm_algo_info_t *, buffer_t *);
extern const tpm_evdigest_t *	digest_compute(const tpm_algo_info_t *, const void *, unsigned int);
extern const tpm_evdigest_t *	digest_from_file(const tpm_algo_info_t *algo_info, const char *filename, int flags);

extern const tpm_algo_info_t *	__digest_by_tpm_alg(unsigned int, const tpm_algo_info_t *, unsigned int);

extern void			cert_table_free(cert_table_t *);
extern parsed_cert_t *		pkcs7_extract_signer(buffer_t *);

extern parsed_cert_t *		cert_parse(const buffer_t *);
extern void			parsed_cert_free(parsed_cert_t *);
extern const char *		parsed_cert_subject(const parsed_cert_t *);
extern const char *		parsed_cert_issuer(const parsed_cert_t *);
extern bool			parsed_cert_issued_by(const parsed_cert_t *cert, const parsed_cert_t *potential_issuer);

#endif /* DIGEST_H */
