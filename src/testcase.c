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
#include <assert.h>

#include "testcase.h"
#include "digest.h"
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
	char *			hash_log;

	FILE *			hash_log_fp;
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

static inline char *
testcase_make_file(testcase_t *tc, const char *relative)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%s", tc->base_directory, relative);
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
	tc->hash_log = testcase_make_file(tc, "hash.log");

	return tc;
}

void
testcase_free(testcase_t *tc)
{
	drop_string(&tc->base_directory);
	drop_string(&tc->efi_directory);
	drop_string(&tc->bsa_directory);
	drop_string(&tc->gpt_directory);
	drop_string(&tc->partition_directory);
	drop_string(&tc->disk_directory);
	drop_string(&tc->hash_log);

	if (tc->hash_log_fp != NULL) {
		fclose(tc->hash_log_fp);
		tc->hash_log_fp = NULL;
	}
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

/* disambiguate path */
static const char *
canon_path(const char *path)
{
	static char rpath[PATH_MAX];
	char *save_path, *comp, *s;
	char *components[PATH_MAX / 2];
	unsigned int i, ncomponents = 0;
	char *dst;

	if (strlen(path) >= sizeof(rpath))
		fatal("%s: path too long (%s)\n", __func__, path);

	while (*path == '/')
		++path;

	save_path = strdup(path);
	for (s = save_path; *comp; ) {
		comp = s;
		while (*s) {
			if (*s == '/') {
				*s++ = '\0';
				break;
			}
			++s;
		}

		if (!strcmp(comp, ".")) {
			/* just consume the "." component */
		} else
		if (!strcmp(comp, "..")) {
			if (ncomponents)
				--ncomponents;
		} else
		if (*comp != '\0') {
			assert(ncomponents < PATH_MAX / 2);
			components[ncomponents++] = comp;
		}
	}

	if (ncomponents == 0)
		return "/";

	dst = rpath;
	for (i = 0; i < ncomponents; ++i) {
		*dst++ = '/';
		strcpy(dst, components[i]);
		dst += strlen(dst);
	}

	// debug("%s(/%s) -> %s\n", __func__, path, rpath);

	drop_string(&save_path);
	return rpath;
}

static FILE *
testcase_hash_log_open(testcase_t *tc, const char *mode)
{
	if (tc->hash_log_fp == NULL) {
		tc->hash_log_fp = fopen(tc->hash_log, mode);
		if (tc->hash_log_fp == NULL)
			fatal("Unable to open %s: %m\n", tc->hash_log);
	} else if (mode[0] == 'r') {
		rewind(tc->hash_log_fp);
	}

	return tc->hash_log_fp;
}

static void
testcase_record_digest(testcase_t *tc, const char *klass, const char *path, const tpm_evdigest_t *md)
{
	FILE *fp = testcase_hash_log_open(tc, "w");

	fprintf(fp, "%s %s %s %s\n",
			digest_algo_name(md), digest_print_value(md),
			klass, canon_path(path));
}

static const tpm_evdigest_t *
testcase_playback_digest(testcase_t *tc, const char *klass, const char *path, const tpm_algo_info_t *algo)
{
	FILE *fp = testcase_hash_log_open(tc, "r");
	const char *algo_name = algo->openssl_name;
	static tpm_evdigest_t md;
	char linebuf[256];

	path = canon_path(path);

	while (fgets(linebuf, sizeof(linebuf), fp) != NULL) {
		char *words[16], *word;
		unsigned int nwords = 0;

		/* chop */
		linebuf[strcspn(linebuf, "\r\n")] = '\0';

		word = strtok(linebuf, ": ");
		while (word && nwords < 16) {
			words[nwords++] = word;
			word = strtok(NULL, " ");
		}

		if (nwords != 4)
			continue;

		if (strcmp(words[0], algo_name)
		 || strcmp(words[2], klass)
		 || strcmp(words[3], path))
			continue;

		memset(&md, 0, sizeof(md));
		md.size = parse_octet_string(words[1], md.data, sizeof(md.data));
		md.algo = algo;
		if (md.size != algo->digest_size) {
			error("bad %s digest \"%s\" - incorrect length\n", algo->openssl_name, words[1]);
			continue;
		}
		return &md;
	}

	/* fallback - return all zeros */
	error("Did not find digest for %s:%s in hash.log - returning all 0 digest\n", klass, path);
	memset(&md, 0, sizeof(md));
	md.size = algo->digest_size;
	md.algo = algo;
	return &md;
}

void
testcase_record_rootfs_digest(testcase_t *tc, const char *path, const tpm_evdigest_t *md)
{
	testcase_record_digest(tc, "rootfs", path, md);
}

const tpm_evdigest_t *
testcase_playback_rootfs_digest(testcase_t *tc, const char *path, const tpm_algo_info_t *algo)
{
	return testcase_playback_digest(tc, "rootfs", path, algo);
}

void
testcase_record_efi_digest(testcase_t *tc, const char *path, const tpm_evdigest_t *md)
{
	testcase_record_digest(tc, "efi", path, md);
}

const tpm_evdigest_t *
testcase_playback_efi_digest(testcase_t *tc, const char *path, const tpm_algo_info_t *algo)
{
	return testcase_playback_digest(tc, "efi", path, algo);
}
