/*
 * fsroot-config.h
 *
 *  Created on: 21 Sep 2017
 *      Author: Ander Juaristi
 */
#ifndef __FSROOT_CONFIG_H__
#define __FSROOT_CONFIG_H__

#define CONFIG_NOMORE			1
#define CONFIG_OK			0
#define CONFIG_E_NO_SUCH_VALUE		-1
#define CONFIG_E_NON_MATCHING_TYPE	-2
#define CONFIG_E_UNSUPPORTED_TYPE	-3
#define CONFIG_E_UNKNOWN_ERROR		-4
#define CONFIG_E_BADARGS		-5

struct config_st;
typedef struct config_st config_t;

struct config_value_st;
typedef struct config_value_st config_value_t;

config_t *config_init(const char *);
void config_deinit(config_t **);

int config_get_value(config_t *, config_value_t **, const char *);

int config_is_string(config_value_t *);
int config_get_as_string(config_value_t *, char **);

int config_is_iterator(config_value_t *);
int config_iterator_next(config_value_t *, config_value_t **);

void config_destroy_value(config_value_t **);

#endif

