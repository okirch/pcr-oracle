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
#include <string.h>
#include <errno.h>

#include "bufparser.h"
#include "runtime.h" /* just for the flags */

buffer_t *
buffer_read_file(const char *filename, int flags)
{
	bool closeit = true;
	buffer_t *bp;
	struct stat stb;
	int count;
	int fd;

	if (filename == NULL || !strcmp(filename, "-")) {
		closeit = false;
		fd = 0;
	} else
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

	if (closeit)
		close(fd);

	debug("Read %u bytes from %s\n", count, filename);
	bp->wpos = count;
	return bp;
}

bool
buffer_write_file(const char *filename, buffer_t *bp)
{
	unsigned int written = 0;
	int fd, n;
	bool closeit = true;

	if (filename == NULL || !strcmp(filename, "-")) {
		closeit = false;
		fd = 1;
	} else
	if ((fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644)) < 0) {
		fatal("Unable to open file %s: %m\n", filename);
	}

	while ((n = buffer_available(bp)) != 0) {
		n = write(fd, buffer_read_pointer(bp), n);
		if (n < 0)
			fatal("write error on %s: %m\n", filename);

		buffer_skip(bp, n);
		written += n;
	}

	if (closeit)
		close(fd);

	// debug("Wrote %u bytes to %s\n", written, filename);
	return true;
}
