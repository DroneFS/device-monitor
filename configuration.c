/*
 * configuration.c
 *
 *  Created on: 5 Dec 2017
 *      Author: Ander Juaristi
 */
#include <string.h>
#include "configuration.h"

int config_init(config_t *c, const char *filename)
{
	char *p;

	if (!filename || !*filename)
		return CONFIG_E_BADARGS;

	p = strrchr(filename, '.');

	if (!p || strncmp(p, ".lua", 4))
		return config_init_xml(c, filename);
	else
		return config_init_lua(c, filename);
}
