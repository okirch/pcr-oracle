

#ifndef RSA_H
#define RSA_H

#include <tss2_tpm2_types.h>

typedef struct tpm_rsa_key	tpm_rsa_key_t;

extern tpm_rsa_key_t *	tpm_rsa_key_read_public(const char *pathname);
extern tpm_rsa_key_t *	tpm_rsa_key_read_private(const char *pathname);
extern void		tpm_rsa_key_free(tpm_rsa_key_t *key);
extern int		tpm_rsa_sign(const tpm_rsa_key_t *,
				const void *tbs_data, size_t tbs_len,
				void *sig_data, size_t sig_size);

extern TPM2B_PUBLIC *	tpm_rsa_key_to_tss2(const tpm_rsa_key_t *key);

#endif /* RSA_H */
