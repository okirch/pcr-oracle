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

extern file_locator_t *	runtime_locate_file(const char *fs_dev, const char *path);
extern void		file_locator_free(file_locator_t *);
extern const char *	file_locator_get_full_path(const file_locator_t *);
extern buffer_t *	runtime_read_file(const char *pathname, int flags);
extern buffer_t *	runtime_read_efi_variable(const char *var_name);
extern char *		runtime_disk_for_partition(const char *part_dev);
extern char *		runtime_blockdev_by_partuuid(const char *uuid);
extern int		runtime_blockdev_open(const char *dev);
extern buffer_t *	runtime_blockdev_read_lba(int fd, unsigned int block, unsigned int count);

static inline unsigned int
runtime_blockdev_bytes_to_sectors(unsigned int size)
{
	/* hard coding sector size for now */
	return (size + 511) / 512;
}

#endif /* RUNTIME_H */
