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
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "testcase.h"
#include "runtime.h"
#include "bufparser.h"
#include "util.h"

struct testcase {
	char *			base_directory;
	char *			efi_directory;
	char *			bsa_directory;
	char *			gpt_directory;
	char *			partition_directory;
	char *			disk_directory;
};

struct testcase_block_dev {
	char *			name;
	int			fd;
};

static inline const char *
get_basename(const char *path)
{
	const char *s;

	/* skip over /dev/ prefix */
	if ((s = strrchr(path, '/')) != NULL)
		path = ++s;
	return path;
}

static inline const char *
get_dirname(const char *path)
{
	static char rpath[PATH_MAX];
	char *s;

	strncpy(rpath, path, sizeof rpath);

	/* skip over /dev/ prefix */
	if ((s = strrchr(rpath, '/')) != NULL) {
		while (s > rpath && *s == '/')
			*s-- = '\0';
	}

	return rpath;
}

static inline bool
testcase_mkdir_p(char *path)
{
	char *s;
	bool ok;

	debug("%s(%s)\n", __func__, path);
	if (mkdir(path, 0700) >= 0 || errno == EEXIST)
		return true;

	if (errno != ENOENT)
		fatal("Unable to create directory %s: %m\n", path);

	if (!(s = strrchr(path, '/')))
		return false;

	while (s > path && s[-1] == '/')
		--s;
	*s = '\0';
	ok = testcase_mkdir_p(path);
	*s = '/';

	if (ok && mkdir(path, 0700) >= 0)
		return true;

	return false;
}

static inline char *
testcase_make_subdir(testcase_t *tc, const char *relative)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", tc->base_directory, relative);
	if (!testcase_mkdir_p(path))
		fatal("Unable to create directory %s\n", path);

	return strdup(path);
}

static int
testcase_create_file(const char *directory, const char *name)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", directory, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 && errno == ENOENT) {
		char *s;

		debug("%s: %m\n", path);
		s = strrchr(path, '/');
		*s = '\0';
		(void) testcase_mkdir_p(path);
		*s = '/';

		fd = open(path, O_WRONLY | O_CREAT, 0600);
	}

	if (fd < 0)
		fatal("Unable to create %s: %m\n", path);

	return fd;
}

static int
testcase_open_file(const char *directory, const char *name)
{
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", directory, name);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		fatal("Unable to open %s: %m\n", path);

	return fd;
}

static void
testcase_create_symlink(const char *directory, const char *name, const char *target)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", directory, name);
	(void) unlink(path);
	if (symlink(target, path) < 0)
		fatal("Cannot create symlink %s -> %s: %m\n", path, target);
}

static char *
testcase_read_symlink(const char *directory, const char *name, const char *default_dir)
{
	char path[PATH_MAX], target[PATH_MAX], result[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", directory, name);
	if (readlink(path, target, sizeof(target)) < 0)
		fatal("Cannot read symlink %s: %m\n", path);

	if (target[0] != '/' && default_dir) {
		snprintf(result, sizeof(result), "%s/%s", default_dir, target);
		return strdup(result);
	}

	return strdup(target);
}

static void
testcase_write_buffer(int fd, const buffer_t *bp, const char *name)
{
	unsigned int written = 0, total;
	int n;

	written = bp->rpos;
	total = bp->wpos;

	while (written < total) {
		n = write(fd, bp->data + written, total - written);
		if (n < 0)
			fatal("error writing testcase file %s: %m\n", name);
		written += n;
	}
}

static void
testcase_write_file(const char *directory, const char *name, const buffer_t *bp)
{
	int fd;

	fd = testcase_create_file(directory, name);
	testcase_write_buffer(fd, bp, name);
	close(fd);
}

static buffer_t *
testcase_read_file(const char *directory, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", directory, name);
	return runtime_read_file(path, 0);
}

testcase_t *
testcase_alloc(const char *dirpath)
{
	testcase_t *tc;

	tc = calloc(1, sizeof(*tc));
	assign_string(&tc->base_directory, dirpath);

	if (!testcase_mkdir_p(tc->base_directory))
		fatal("%s: unable to create directory %s\n", __func__, dirpath);

	tc->efi_directory = testcase_make_subdir(tc, "efivars");
	tc->bsa_directory = testcase_make_subdir(tc, "images");
	tc->gpt_directory = testcase_make_subdir(tc, "gpts");
	tc->partition_directory = testcase_make_subdir(tc, "partitions");
	tc->disk_directory = testcase_make_subdir(tc, "disks");

	return tc;
}

void
testcase_free(testcase_t *tc)
{
	drop_string(&tc->base_directory);
	drop_string(&tc->efi_directory);
	drop_string(&tc->gpt_directory);
	drop_string(&tc->partition_directory);
}

void
testcase_record_sysfs_file(testcase_t *tc, const char *path, const char *nickname)
{
	unsigned char buffer[8192];
	int ifd, ofd, count;

	debug("%s()\n", __func__);
	ifd = open(path, O_RDONLY);
	if (ifd < 0)
		fatal("%s: %m\n", path);

	ofd = testcase_create_file(tc->base_directory, nickname);
	do {
		int n;

		count = read(ifd, buffer, sizeof(buffer));
		if (count < 0)
			fatal("%s: %m\n", path);

		n = write(ofd, buffer, count);
		if (n < 0)
			fatal("cannot write %s recording: %m\n", path);
		if (n != count)
			fatal("short write on %s recording: %m\n", path);
	} while (count);
	close(ifd);
	close(ofd);
}

int
testcase_playback_sysfs_file(testcase_t *tc, const char *nickname)
{
	return testcase_open_file(tc->base_directory, nickname);
}

void
testcase_record_efi_variable(testcase_t *tc, const char *name, const buffer_t *data)
{
	testcase_write_file(tc->efi_directory, name, data);
}

buffer_t *
testcase_playback_efi_variable(testcase_t *tc, const char *name)
{
	return testcase_read_file(tc->efi_directory, name);
}

void
testcase_record_efi_application(testcase_t *tc, const char *partition, const char *application, const buffer_t *data)
{
	char path[PATH_MAX];

	partition = get_basename(partition);

	snprintf(path, sizeof path, "%s/%s", partition, application);
	testcase_write_file(tc->bsa_directory, path, data);
}

buffer_t *
testcase_playback_efi_application(testcase_t *tc, const char *partition, const char *application)
{
	char path[PATH_MAX];

	partition = get_basename(partition);

	snprintf(path, sizeof path, "%s/%s", partition, application);
	return testcase_read_file(tc->bsa_directory, path);
}

void
testcase_record_partition_uuid(testcase_t *tc, const char *uuid, const char *dev_name)
{
	if (!strncmp(dev_name, "/dev/", 5))
		dev_name += 5;

	testcase_create_symlink(tc->partition_directory, uuid, dev_name);
}

char *
testcase_playback_partition_uuid(testcase_t *tc, const char *uuid)
{
	return testcase_read_symlink(tc->partition_directory, uuid, "/dev");
}

void
testcase_record_partition_disk(testcase_t *tc, const char *dev_name, const char *disk_name)
{
	testcase_create_symlink(tc->disk_directory, dev_name, disk_name);
}

char *
testcase_playback_partition_disk(testcase_t *tc, const char *dev_path)
{
	/* skip over /dev/ prefix */
	dev_path = get_basename(dev_path);

	return testcase_read_symlink(tc->disk_directory, dev_path, "/dev");
}

testcase_block_dev_t *
testcase_record_block_dev(testcase_t *tc, const char *dev_path)
{
	testcase_block_dev_t *io;
	int fd;

	/* skip over /dev/ prefix */
	dev_path = get_basename(dev_path);

	if ((fd = testcase_create_file(tc->gpt_directory, dev_path)) < 0)
		return NULL;

	io = calloc(1, sizeof(*io));
	io->name = strdup(dev_path);
	io->fd = fd;

	return io;
}

void
testcase_block_dev_write(testcase_block_dev_t *io, unsigned long offset, const buffer_t *bp)
{
	if (lseek(io->fd, offset, SEEK_SET) < 0)
		fatal("%s: cannot seek: %m\n", io->name);

	testcase_write_buffer(io->fd, bp, io->name);
}

void
testcase_block_dev_close(testcase_block_dev_t *io)
{
	drop_string(&io->name);
	close(io->fd);
	free(io);
}

int
testcase_playback_block_dev(testcase_t *tc, const char *dev_path)
{
	/* skip over /dev/ prefix */
	dev_path = get_basename(dev_path);

	return testcase_open_file(tc->gpt_directory, dev_path);
}

FILE *
testcase_record_pcrs(testcase_t *tc, const char *name)
{
	int fd;

	if ((fd = testcase_create_file(tc->base_directory, name)) < 0)
		return NULL;

	return fdopen(fd, "w");
}

FILE *
testcase_playback_pcrs(testcase_t *tc, const char *name)
{
	int fd;

	if ((fd = testcase_open_file(tc->base_directory, name)) < 0)
		return NULL;

	return fdopen(fd, "r");
}
