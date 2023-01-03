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
#include "digest.h"
#include "testcase.h"
#include "util.h"

struct file_locator {
	char *		partition;
	char *		relative_path;

	char *		mount_point;
	bool		is_mounted;

	char *		full_path;
};

struct block_dev_io {
	int		fd;
	unsigned int	sector_size;

	testcase_block_dev_t *recording;
};

static testcase_t *	testcase_recording;
static testcase_t *	testcase_playback;

/*
 * Testcase handling
 */
void
runtime_record_testcase(testcase_t *tc)
{
	debug("Starting testcase recording\n");
	testcase_recording = tc;
}

void
runtime_replay_testcase(testcase_t *tc)
{
	debug("Starting testcase playback\n");
	testcase_playback = tc;
}

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

	if (!(dirname = mkdtemp(template))) {
		error("Cannot create temporary mount point for EFI partition");
		return NULL;
	}

	if (mount(device_path, dirname, "vfat", 0, NULL) < 0) {
		(void) rmdir(dirname);
		error("Unable to mount %s on %s\n", device_path, dirname);
		return NULL;
	}

	assign_string(&loc->mount_point, dirname);
	loc->is_mounted = true;

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
__system_read_efi_variable(const char *var_name)
{
	char filename[PATH_MAX];
	buffer_t *result;

	if (testcase_playback)
		return testcase_playback_efi_variable(testcase_playback, var_name);

	/* First, try new efivars interface */
	snprintf(filename, sizeof(filename), "/sys/firmware/efi/efivars/%s", var_name);
	result = buffer_read_file(filename, RUNTIME_SHORT_READ_OKAY | RUNTIME_MISSING_FILE_OKAY);
	if (result != NULL) {
		/* Skip over 4 bytes of variable attributes */
		buffer_skip(result, 4);
	} else {
		/* Fall back to old sysfs entries with their 1K limitation */
		snprintf(filename, sizeof(filename), "/sys/firmware/efi/vars/%s/data", var_name);
		result = buffer_read_file(filename, RUNTIME_SHORT_READ_OKAY);
	}

	if (result && testcase_recording)
		testcase_record_efi_variable(testcase_recording, var_name, result);

	return result;
}

static int
runtime_open_sysfs_file(const char *sysfs_path, const char *nickname)
{
	int fd;

	if (testcase_playback)
		return testcase_playback_sysfs_file(testcase_playback, nickname);

	fd = open(sysfs_path, O_RDONLY);
	if (fd < 0)
		return -1;

	if (testcase_recording)
		testcase_record_sysfs_file(testcase_recording, sysfs_path, nickname);
	return fd;
}

int
runtime_open_eventlog(const char *override_path)
{
	const char *eventlog_path = "/sys/kernel/security/tpm0/binary_bios_measurements";
	int fd;

	if (override_path)
		eventlog_path = override_path;

	fd = runtime_open_sysfs_file(eventlog_path, "tpm_measurements");
	if (fd < 0)
		error("Unable to open TPM event log %s: %m\n", eventlog_path);
	return fd;

}

int
runtime_open_ima_measurements(void)
{
	const char *ima_path = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements";

	return runtime_open_sysfs_file(ima_path, "ima_measurements");
}

buffer_t *
runtime_read_file(const char *path, int flags)
{
	return buffer_read_file(path, flags);
}

bool
runtime_write_file(const char *path, buffer_t *bp)
{
	return buffer_write_file(path, bp);
}

buffer_t *
runtime_read_efi_variable(const char *var_name)
{
	return __system_read_efi_variable(var_name);
}

const tpm_evdigest_t *
runtime_digest_efi_file(const tpm_algo_info_t *algo, const char *path)
{
	const tpm_evdigest_t *md;

	if (testcase_playback)
		return testcase_playback_efi_digest(testcase_playback, path, algo);

	md = digest_from_file(algo, path, 0);
	if (md && testcase_recording)
		testcase_record_efi_digest(testcase_recording, path, md);

	return md;
}

const tpm_evdigest_t *
runtime_digest_rootfs_file(const tpm_algo_info_t *algo, const char *path)
{
	const tpm_evdigest_t *md;

	if (testcase_playback)
		return testcase_playback_rootfs_digest(testcase_playback, path, algo);

	md = digest_from_file(algo, path, 0);
	if (md && testcase_recording)
		testcase_record_rootfs_digest(testcase_recording, path, md);

	return md;
}

buffer_t *
runtime_read_efi_application(const char *partition, const char *application)
{
        file_locator_t *loc;
	const char *fullpath;
	buffer_t *result;

	if (testcase_playback)
		return testcase_playback_efi_application(testcase_playback, partition, application);

	debug("%s(%s, %s)\n", __func__, partition, application);
        loc = runtime_locate_file(partition, application);
        if (!loc)
                return NULL;

	if ((fullpath = file_locator_get_full_path(loc)) != NULL)
                result = runtime_read_file(fullpath, 0);

	file_locator_free(loc);

	if (result && testcase_recording)
		testcase_record_efi_application(testcase_recording, partition, application, result);

	return result;
}

char *
runtime_disk_for_partition(const char *part_dev)
{
	char *part_name;
	char sys_block[PATH_MAX];
	char sys_device[PATH_MAX];
	ssize_t link_size;
	char *disk_name;
	size_t r_size;
	char *result;

	if (testcase_playback)
		return testcase_playback_partition_disk(testcase_playback, part_dev);

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

	if (testcase_recording)
		testcase_record_partition_disk(testcase_recording, part_name, disk_name);

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
	char *dev_name;

	if (testcase_playback)
		return testcase_playback_partition_uuid(testcase_playback, uuid);

	snprintf(pathbuf, sizeof(pathbuf), "/dev/disk/by-partuuid/%s", uuid);
	dev_name = realpath(pathbuf, NULL);

	if (dev_name && testcase_recording)
		testcase_record_partition_uuid(testcase_recording, uuid, dev_name);
	return dev_name;
}

block_dev_io_t *
runtime_blockdev_open(const char *dev)
{
	block_dev_io_t *io;
	int fd;

	if (testcase_playback)
		fd = testcase_playback_block_dev(testcase_playback, dev);
	else
	if ((fd = open(dev, O_RDONLY)) < 0)
		return NULL;

	io = calloc(1, sizeof(*io));
	io->fd = fd;
	io->sector_size = 512;

	if (testcase_recording)
		io->recording = testcase_record_block_dev(testcase_recording, dev);

	return io;
}

void
runtime_blockdev_close(block_dev_io_t *io)
{
	close(io->fd);
	io->fd = -1;

	if (io->recording) {
		testcase_block_dev_close(io->recording);
		io->recording = NULL;
	}

	free(io);
}

unsigned int
runtime_blockdev_bytes_to_sectors(const block_dev_io_t *io, unsigned int size)
{
	return (size + io->sector_size - 1) / io->sector_size;
}

buffer_t *
runtime_blockdev_read_lba(block_dev_io_t *io, unsigned int block, unsigned int count)
{
	unsigned long offset = block * io->sector_size;
	unsigned int bytes;
	buffer_t *result;
	int n;

	if (lseek(io->fd, offset, SEEK_SET) < 0) {
		error("block dev seek: %m\n");
		return NULL;
	}

	bytes = io->sector_size * count;

	result = buffer_alloc_write(bytes);
	n = read(io->fd, buffer_write_pointer(result), bytes);
	if (n < 0) {
		error("block dev read: %m\n");
		goto failed;
	}
	if (n < bytes) {
		error("block dev read: %m\n");
		goto failed;
	}
	result->wpos += bytes;

	if (io->recording)
		testcase_block_dev_write(io->recording, offset, result);

	return result;

failed:
	buffer_free(result);
	return NULL;
}

FILE *
runtime_maybe_record_pcrs(void)
{
	if (testcase_recording)
		return testcase_record_pcrs(testcase_recording, "current-pcrs");
	return NULL;
}

FILE *
runtime_maybe_playback_pcrs(void)
{
	if (testcase_playback)
		return testcase_playback_pcrs(testcase_playback, "current-pcrs");
	return NULL;
}
