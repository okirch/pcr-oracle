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

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include "runtime.h"

static buffer_t *
__system_read_file(const char *filename, int flags)
{
	buffer_t *bp;
	struct stat stb;
	int count;
	int fd;

	debug("Reading %s\n", filename);
	if ((fd = open(filename, O_RDONLY)) < 0) {
		if (errno == ENOENT && (flags & RUNTIME_MISSING_FILE_OKAY))
			return NULL;

		fatal("Unable to open file %s: %m\n", filename);
	}

	if (fstat(fd, &stb) < 0)
		fatal("Cannot stat %s: %m\n", filename);

	bp = buffer_alloc_write(stb.st_size);
	if (bp == NULL)
		fatal("Cannot allocate buffer of %lu bytes for %s: %m\n",
				(unsigned long) stb.st_size,
				filename);

	count = read(fd, bp->data, stb.st_size);
	if (count < 0)
		fatal("Error while reading from %s: %m\n", filename);

	if (flags & RUNTIME_SHORT_READ_OKAY) {
		/* NOP */
	} else if (count != stb.st_size) {
		fatal("Short read from %s\n", filename);
	}

	close(fd);

	debug("Read %u bytes from %s\n", count, filename);
	bp->wpos = count;
	return bp;
}

static buffer_t *
__system_read_efi_variable(const char *var_name)
{
	char filename[PATH_MAX];
	buffer_t *result;

	/* First, try new efivars interface */
	snprintf(filename, sizeof(filename), "/sys/firmware/efi/efivars/%s", var_name);
	result = __system_read_file(filename, RUNTIME_SHORT_READ_OKAY | RUNTIME_MISSING_FILE_OKAY);
	if (result != NULL) {
		/* Skip over 4 bytes of variable attributes */
		buffer_skip(result, 4);
		return result;
	}

	/* Fall back to old sysfs entries with their 1K limitation */
	snprintf(filename, sizeof(filename), "/sys/firmware/efi/vars/%s/data", var_name);
	return __system_read_file(filename, RUNTIME_SHORT_READ_OKAY);
}

buffer_t *
runtime_read_file(const char *path, int flags)
{
	return __system_read_file(path, flags);
}

buffer_t *
runtime_read_efi_variable(const char *var_name)
{
	return __system_read_efi_variable(var_name);
}

char *
runtime_disk_for_partition(const char *part_dev)
{
	int len = strlen(part_dev);
	char *result;

	if (len == 0 || !isdigit(part_dev[len-1]))
		return NULL;

	result = strdup(part_dev);
	while (len && isdigit(result[len-1]))
		result[--len] = '\0';
	return result;
}

int
runtime_blockdev_open(const char *dev)
{
	return open(dev, O_RDONLY);
}

buffer_t *
runtime_blockdev_read_lba(int fd, unsigned int block, unsigned int count)
{
	static const unsigned int sector_size = 512;
	unsigned int bytes;
	buffer_t *result;
	int n;

	if (lseek(fd, block * sector_size, SEEK_SET) < 0) {
		error("block dev seek: %m\n");
		return NULL;
	}

	bytes = sector_size * count;

	result = buffer_alloc_write(bytes);
	n = read(fd, buffer_write_pointer(result), bytes);
	if (n < 0) {
		error("block dev read: %m\n");
		goto failed;
	}
	if (n < bytes) {
		error("block dev read: %m\n");
		goto failed;
	}
	result->wpos += bytes;
	return result;

failed:
	buffer_free(result);
	return NULL;
}
