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

#include <stdio.h>

#include "oracle.h"

/*
 * For the time being, PCR prediction does do anything with IMA
 * except making sure we're ignoring PCR 10 if IMA is active.
 */

#define IMA_RUNTIME_MEASUREMENTS	"/sys/kernel/security/integrity/ima/ascii_runtime_measurements"

bool
ima_is_active(void)
{
	FILE *fp;

	if (!(fp = fopen(IMA_RUNTIME_MEASUREMENTS, "r")))
		return false;

	fclose(fp);
	return true;
}
