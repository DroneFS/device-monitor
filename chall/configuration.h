/*
 * configuration.h
 *
 *  Created on: 21 Sep 2017
 *      Author: Ander Juaristi
 */
#ifndef __FSROOT_CONFIG_H__
#define __FSROOT_CONFIG_H__
#include "list.h"

#define CONFIG_NOMORE			1
#define CONFIG_OK			0
#define CONFIG_E_NO_SUCH_VALUE		-1
#define CONFIG_E_NON_MATCHING_TYPE	-2
#define CONFIG_E_UNSUPPORTED_TYPE	-3
#define CONFIG_E_UNKNOWN_ERROR		-4
#define CONFIG_E_BADARGS		-5

typedef struct config_st
{
	void (*deinit) (struct config_st **);
	size_t (*get_challenges_list) (struct config_st *, list_head_t *);
	char * (*get_crypto_algorithm) (struct config_st *);

	void *priv;
} config_t;

int config_init(config_t *, const char *);
int config_init_xml(config_t *, const char *);
int config_init_lua(config_t *, const char *);

#endif
