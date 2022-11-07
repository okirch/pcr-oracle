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

#include <sys/utsname.h>
#include <limits.h>
#include <dirent.h>
#include "oracle.h"
#include "util.h"
#include "runtime.h"

#define PLATFORM_EFI_INSTALLDIR		"/usr/share/efi"

buffer_t *
platform_read_shim_vendor_cert(void)
{
	char path[PATH_MAX], rpath[PATH_MAX];
	struct utsname uts;
	int len;

	if (uname(&uts) < 0) {
		error("uname: %m\n");
		return NULL;
	}

	debug("Locating shim vendor cert in %s/%s\n", PLATFORM_EFI_INSTALLDIR, uts.machine);

	/* At least on SUSE, shim.efi is a symlink to shim-$OS.efi (where OS is sles, opensuse etc).
	 * The vendor certificate that was embedded in this binary is shipped as
	 * shim-$OS.der in the same directory.
	 */
	snprintf(path, sizeof(path), "%s/%s/shim.efi", PLATFORM_EFI_INSTALLDIR, uts.machine);
	if (realpath(path, rpath) == NULL) {
		error("%s: %\n", path);
		return NULL;
	}

	len = strlen(rpath);
	if (len <= 4 || strcmp(rpath + len - 4, ".efi")) {
		error("%s: does not have suffix .efi\n", path);
		return NULL;
	}

	strcpy(rpath + len - 4, ".der");
	return runtime_read_file(rpath, 0);
}
