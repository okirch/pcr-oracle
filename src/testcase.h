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

#ifndef TESTCASE_H
#define TESTCASE_H

#include "types.h"

typedef struct testcase_block_dev testcase_block_dev_t;

extern testcase_t *		testcase_alloc(const char *dirpath);
extern void			testcase_free(testcase_t *);
extern void			testcase_record_sysfs_file(testcase_t *tc, const char *, const char *);
extern void			testcase_record_efi_variable(testcase_t *, const char *name, const buffer_t *);
extern void			testcase_record_efi_application(testcase_t *, const char *partition, const char *application, const buffer_t *);
extern void			testcase_record_partition_uuid(testcase_t *, const char *uuid, const char *dev_name);
extern void			testcase_record_partition_disk(testcase_t *, const char *dev_name, const char *disk_name);
extern testcase_block_dev_t *	testcase_record_block_dev(testcase_t *, const char *dev_path);
extern void			testcase_block_dev_write(testcase_block_dev_t *, unsigned long offset, const buffer_t *);
extern void			testcase_block_dev_close(testcase_block_dev_t *);

extern int			testcase_playback_sysfs_file(testcase_t *, const char *);
extern buffer_t *		testcase_playback_efi_variable(testcase_t *, const char *name);
extern buffer_t *		testcase_playback_efi_application(testcase_t *, const char *partition, const char *application);
extern char *			testcase_playback_partition_uuid(testcase_t *, const char *uuid);
extern char *			testcase_playback_partition_disk(testcase_t *, const char *dev_name);
extern int			testcase_playback_block_dev(testcase_t *, const char *dev_path);

extern void			testcase_record_rootfs_digest(testcase_t *, const char *path, const tpm_evdigest_t *md);
extern const tpm_evdigest_t *	testcase_playback_rootfs_digest(testcase_t *, const char *path, const tpm_algo_info_t *algo);
extern void			testcase_record_efi_digest(testcase_t *, const char *path, const tpm_evdigest_t *md);
extern const tpm_evdigest_t *	testcase_playback_efi_digest(testcase_t *, const char *path, const tpm_algo_info_t *algo);

#include <stdio.h>

extern FILE *			testcase_record_pcrs(testcase_t *, const char *name);
extern FILE *			testcase_playback_pcrs(testcase_t *, const char *name);

#endif /* TESTCASE_H */
