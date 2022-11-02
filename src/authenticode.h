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

#ifndef AUTHENTICODE_H
#define AUTHENTICODE_H

#include "types.h"

extern pecoff_image_info_t *pecoff_inspect(const char *path, const char *display_name);
extern void		pecoff_image_info_free(pecoff_image_info_t *);
extern tpm_evdigest_t *	authenticode_get_digest(pecoff_image_info_t *, digest_ctx_t *);
extern cert_table_t *	authenticode_get_certificate_table(const pecoff_image_info_t *img);
extern buffer_t *	authenticode_get_signer(const pecoff_image_info_t *);

#endif /* AUTHENTICODE_H */

