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
#include <sys/mount.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

#include "runtime.h"
#include "bufparser.h"
#include "util.h"

struct file_locator {
	char *		partition;
	char *		relative_path;

	char *		mount_point;
	bool		is_mounted;

	char *		full_path;
};

file_locator_t *
runtime_locate_file(const char *device_path, const char *file_path)
{
	char template[] = "/tmp/efimnt.XXXXXX";
	char fullpath[PATH_MAX];
	file_locator_t *loc;
	char *dirname;

	loc = calloc(1, sizeof(*loc));
	assign_string(&loc->partition, device_path);
	assign_string(&loc->relative_path, file_path);

	if (!(dirname = mkdtemp(template)))
		fatal("Cannot create temporary mount point for EFI partition");

	if (mount(device_path, dirname, "vfat", 0, NULL) < 0) {
		(void) rmdir(dirname);
		fatal("Unable to mount %s on %s\n", device_path, dirname);
	}

	assign_string(&loc->mount_point, dirname);

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dirname, file_path);
	assign_string(&loc->full_path, fullpath);

	return loc;
}

void
file_locator_unmount(file_locator_t *loc)
{
	if (!loc->is_mounted)
		return;

	if (umount(loc->mount_point) < 0)
		fatal("unable to unmount temporary directory %s: %m\n", loc->mount_point);

	if (rmdir(loc->mount_point) < 0)
		fatal("unable to remove temporary directory %s: %m\n", loc->mount_point);

	drop_string(&loc->mount_point);
	drop_string(&loc->full_path);
	loc->is_mounted = false;
}

void
file_locator_free(file_locator_t *loc)
{
	file_locator_unmount(loc);

	drop_string(&loc->partition);
	drop_string(&loc->relative_path);
	drop_string(&loc->full_path);
}

const char *
file_locator_get_full_path(const file_locator_t *loc)
{
	return loc->full_path;
}

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
	char *part_name;
	char sys_block[PATH_MAX];
	char sys_device[PATH_MAX];
	ssize_t link_size;
	char *disk_name;
	size_t r_size;
	char *result;

	if (len == 0 || !isdigit(part_dev[len-1]))
		return NULL;

	/* Get the disk name from the sysfs path */
	/* example:
	 *   To get the disk device name of /dev/nvme0n1p1
	 *
	 *   Look into the link to the sysfs block device:
	 *   $ ls -l /sys/class/block/nvme0n1p1
	 *   lrwxrwxrwx 1 root root 0 Oct 19 09:53 /sys/class/block/nvme0n1p1 -> ../../devices/pci0000:00/0000:00:06.0/0000:02:00.0/nvme/nvme0/nvme0n1/nvme0n1p1
	 *
	 *   Trace back the upper level directory to get "nvme0n1"
	 *   and return "/dev/nvme0n1"
	 */
	part_name = strrchr(part_dev, '/')+1;

	snprintf(sys_block, PATH_MAX, "/sys/class/block/%s", part_name);

	link_size = readlink(sys_block, sys_device, PATH_MAX);
	if (link_size < 0) {
		error("Error when reading the link of %s: %m\n", sys_block);
		return NULL;
	} else if (link_size >= PATH_MAX) {
		error("Error insufficient buffer size for the link of %s\n", sys_block);
		return NULL;
	}

	*strrchr(sys_device, '/') = '\0';
	disk_name = strrchr(sys_device, '/')+1;

	r_size = strlen("/dev/") + strlen(disk_name) + 1;
	result = malloc(r_size);
	if (result == NULL) {
		error("Error when allocating buffer: %m\n");
		return NULL;
	}
	snprintf(result, r_size, "/dev/%s", disk_name);

	return result;
}

char *
runtime_blockdev_by_partuuid(const char *uuid)
{
	char pathbuf[PATH_MAX];

	snprintf(pathbuf, sizeof(pathbuf), "/dev/disk/by-partuuid/%s", uuid);
	return realpath(pathbuf, NULL);
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
