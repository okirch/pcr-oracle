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

#ifndef RSA_H
#define RSA_H

#include <tss2_tpm2_types.h>

typedef struct tpm_rsa_key	tpm_rsa_key_t;

extern tpm_rsa_key_t *	tpm_rsa_key_read_public(const char *pathname);
extern tpm_rsa_key_t *	tpm_rsa_key_read_private(const char *pathname);
extern bool		tpm_rsa_key_write_private(const char *pathname,
				const tpm_rsa_key_t *key);
extern void		tpm_rsa_key_free(tpm_rsa_key_t *key);
extern tpm_rsa_key_t *	tpm_rsa_generate(unsigned int bits);
extern int		tpm_rsa_sign(const tpm_rsa_key_t *,
				const void *tbs_data, size_t tbs_len,
				void *sig_data, size_t sig_size);

extern TPM2B_PUBLIC *	tpm_rsa_key_to_tss2(const tpm_rsa_key_t *key);

#endif /* RSA_H */
