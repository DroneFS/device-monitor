/*
 * fsroot-config.c
 *
 *  Created on: 21 Sep 2017
 *      Author: Ander Juaristi
 */
#include <stdio.h>
#include <string.h>
#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
#include "mm.h"
#include "fsroot-config.h"

enum config_value_types
{
	UNDEFINED = 0,
	STRING,
	TABLE
};

struct config_st
{
	lua_State *L;
};

struct config_value_st
{
	config_t *c;
	enum config_value_types type;
	char *str;
	int idx;
};

config_t *config_init(const char *filename)
{
	config_t *c = mm_new0(config_t);

	c->L = luaL_newstate();
	if (!c->L)
		goto error;

	if (luaL_loadfile(c->L, filename) || lua_pcall(c->L, 0, 0, 0))
		goto error;

	return c;

error:
	mm_free(c);
	return NULL;
}

void config_deinit(config_t **c)
{
	if (c && *c) {
		lua_close((*c)->L);
		mm_free(*c);
	}
}

static int generate_value_from_lua_stack(config_t *c, config_value_t **out_val)
{
	const char *str;
	config_value_t *val = (*out_val == NULL ?
			       mm_new0(config_value_t) :
			       *out_val);

	if (lua_isstring(c->L, -1)) {
		val->type = STRING;
		if (!(str = lua_tostring(c->L, -1)))
			goto error_unknown;
		val->str = strdup(str);
		/* Remove the string from the stack */
		lua_pop(c->L, 1);
	} else if (lua_istable(c->L, -1)) {
		val->type = TABLE;
		/* Table indexes in Lua start at one */
		val->idx = 1;
		/* Leave the table at the top of the stack */
	} else {
		goto error;
	}

	val->c = c;
	if (*out_val == NULL)
		*out_val = val;
	return CONFIG_OK;

error:
	mm_free(val);
	return CONFIG_E_UNSUPPORTED_TYPE;
error_unknown:
	mm_free(val);
	return CONFIG_E_UNKNOWN_ERROR;
}

static inline int is_iterator(config_value_t *val)
{
	return (val->type == TABLE);
}

static void config_free_value(config_value_t *val)
{
	if (val->type == STRING)
		mm_free(val->str);
	else
		lua_pop(val->c->L, 1);

	val->idx = 0;
	val->type = UNDEFINED;
}

int config_get_value(config_t *c, config_value_t **val, const char *name)
{
	if (!c || !c->L || !val || !name || !*name)
		return CONFIG_E_BADARGS;

	if (*val)
		config_free_value(*val);

	lua_getglobal(c->L, name);
	return generate_value_from_lua_stack(c, val);
}

int config_is_string(config_value_t *val)
{
	if (!val)
		return CONFIG_E_BADARGS;

	return (val->type == STRING);
}

int config_get_as_string(config_value_t *val, char **out)
{
	if (val->type != STRING)
		return CONFIG_E_NON_MATCHING_TYPE;

	*out = strdup(val->str);
	return CONFIG_OK;
}

int config_is_iterator(config_value_t *val)
{
	if (!val)
		return CONFIG_E_BADARGS;

	return is_iterator(val);
}

int config_iterator_next(config_value_t *it, config_value_t **val)
{
	lua_State *L;

	if (!it || !it->c->L || !val)
		return CONFIG_E_BADARGS;
	if (!is_iterator(it))
		return CONFIG_E_NON_MATCHING_TYPE;
	if (it->idx == -1)
		return CONFIG_NOMORE;

	L = it->c->L;

	if (!lua_istable(L, -1))
		return CONFIG_NOMORE;

	if (*val)
		config_free_value(*val);

	lua_pushinteger(L, it->idx);
	lua_gettable(L, -2);

	if (!lua_isnil(L, -1)) {
		generate_value_from_lua_stack(it->c, val);
		// lua_pop(L, 1);
		it->idx++;

		return CONFIG_OK;
	} else {
		it->idx = -1;
		return CONFIG_NOMORE;
	}
}

void config_destroy_value(config_value_t **val)
{
	if (val && *val) {
		config_free_value(*val);
		mm_free(*val);
	}
}

