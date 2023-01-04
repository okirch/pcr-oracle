/*
 *   Copyright (C) 2022, 2023 SUSE LLC
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

#include <string.h>
#include <stdio.h>
#include "eventlog.h"

#define SHIM_EFIVAR_GUUID	"605dab50-e046-4300-abb6-3dd810dd8b23"

typedef struct shim_variable {
	const char *		name;
	const char *		rtname;
} shim_variable_t;

static shim_variable_t		shim_variables[] = {
	{ "MokList",		"MokListRT"	},
	{ "MokListX",		"MokListXRT"	},
	{ "MokSBState",		"MokSBStateRT"	},
	{ "MokDBState",		"MokIgnoreDB"	},
	{ "MokListTrusted",	"MokListTrustedRT" },
	{ "MokPolicy",		"MokPolicyRT"	},
	{ "SbatLevel",		"SbatLevelRT"	},

	{ NULL, NULL }
};

static const shim_variable_t *
shim_variable_find(const char *name)
{
	shim_variable_t *var;

	for (var = shim_variables; var->name; ++var) {
		if (!strcmp(var->name, name))
			return var;
	}
	return NULL;
}

bool
shim_variable_name_valid(const char *name)
{
	return shim_variable_find(name) != NULL;
}

const char *
shim_variable_get_rtname(const char *name)
{
	const shim_variable_t *var;

	if (!(var = shim_variable_find(name)))
		return NULL;
	return var->rtname;
}

const char *
shim_variable_get_full_rtname(const char *name)
{
	static char namebuf[128];
	const shim_variable_t *var;

	if (!(var = shim_variable_find(name)))
		return NULL;
	snprintf(namebuf, sizeof(namebuf), "%s-" SHIM_EFIVAR_GUUID, var->rtname);
	return namebuf;
}
