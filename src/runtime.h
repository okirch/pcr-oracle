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

#ifndef RUNTIME_H
#define RUNTIME_H

#include "types.h"

#define RUNTIME_SHORT_READ_OKAY		0x0001
#define RUNTIME_MISSING_FILE_OKAY	0x0002

typedef struct file_locator	file_locator_t;
typedef struct block_dev_io	block_dev_io_t;

extern file_locator_t *	runtime_locate_file(const char *fs_dev, const char *path);
extern void		file_locator_free(file_locator_t *);
extern const char *	file_locator_get_full_path(const file_locator_t *);
extern int		runtime_open_eventlog(const char *override_path);
extern int		runtime_open_ima_measurements(void);
extern buffer_t *	runtime_read_file(const char *pathname, int flags);
extern bool		runtime_write_file(const char *pathname, buffer_t *);
extern buffer_t *	runtime_read_efi_variable(const char *var_name);
extern buffer_t *	runtime_read_efi_application(const char *partition, const char *application);
extern const tpm_evdigest_t *runtime_digest_efi_file(const tpm_algo_info_t *algo, const char *path);
extern const tpm_evdigest_t *runtime_digest_rootfs_file(const tpm_algo_info_t *algo, const char *path);
extern char *		runtime_disk_for_partition(const char *part_dev);
extern char *		runtime_blockdev_by_partuuid(const char *uuid);
extern block_dev_io_t *	runtime_blockdev_open(const char *dev);
extern buffer_t *	runtime_blockdev_read_lba(block_dev_io_t *, unsigned int block, unsigned int count);
extern void		runtime_blockdev_close(block_dev_io_t *);

extern unsigned int	runtime_blockdev_bytes_to_sectors(const block_dev_io_t *, unsigned int size);

extern void		runtime_record_testcase(testcase_t *);
extern void		runtime_replay_testcase(testcase_t *);

#include <stdio.h>

extern FILE *		runtime_maybe_record_pcrs(void);
extern FILE *		runtime_maybe_playback_pcrs(void);

#endif /* RUNTIME_H */
