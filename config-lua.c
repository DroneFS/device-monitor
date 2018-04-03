/*
 * config-lua.c
 *
 *  Created on: 21 Sep 2017
 *      Author: Ander Juaristi
 */
#include <stdio.h>
#include <string.h>

#include "configuration.h"
#include "list.h"
#include "mm.h"

#ifndef HAVE_LUA
int config_init_lua(config_t *c, const char *filename)
{
	return CONFIG_E_UNSUPPORTED_TYPE;
}
#else
#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>

enum config_value_types
{
	UNDEFINED = 0,
	STRING,
	TABLE
};

typedef struct config_value_st
{
	lua_State *L;
	enum config_value_types type;
	char *str;
	int idx;
} config_value_t;

static void config_deinit(config_t **);
static size_t config_get_challenges_list(config_t *, list_head_t *);

int config_init_lua(config_t *c, const char *filename)
{
	lua_State *L = luaL_newstate();
	if (!L)
		return CONFIG_E_UNKNOWN_ERROR;

	if (luaL_loadfile(L, filename) || lua_pcall(L, 0, 0, 0))
		return CONFIG_E_UNKNOWN_ERROR;

	c->deinit = config_deinit;
	c->get_challenges_list = config_get_challenges_list;
	c->priv = L;
	return CONFIG_OK;
}

static void config_deinit(config_t **c)
{
	if (c && *c)
		lua_close((lua_State *)(*c)->priv);
}

static int generate_value_from_lua_stack(lua_State *L, config_value_t **out_val)
{
	const char *str;
	config_value_t *val = (*out_val == NULL ?
			       mm_new0(config_value_t) :
			       *out_val);

	if (lua_isstring(L, -1)) {
		val->type = STRING;
		if (!(str = lua_tostring(L, -1)))
			goto error_unknown;
		val->str = strdup(str);
		/* Remove the string from the stack */
		lua_pop(L, 1);
	} else if (lua_istable(L, -1)) {
		val->type = TABLE;
		/* Table indexes in Lua start at one */
		val->idx = 1;
		/* Leave the table at the top of the stack */
	} else {
		goto error;
	}

	val->L = L;
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
		lua_pop(val->L, 1);

	val->idx = 0;
	val->type = UNDEFINED;
}

static int config_get_value(config_t *c, config_value_t **val, const char *name)
{
	lua_State *L;

	if (!c || !c->priv || !val || !name || !*name)
		return CONFIG_E_BADARGS;

	if (*val)
		config_free_value(*val);

	L = c->priv;
	lua_getglobal(L, name);
	return generate_value_from_lua_stack(L, val);
}

static int config_is_string(config_value_t *val)
{
	if (!val)
		return CONFIG_E_BADARGS;

	return (val->type == STRING);
}

static int config_get_as_string(config_value_t *val, char **out)
{
	if (val->type != STRING)
		return CONFIG_E_NON_MATCHING_TYPE;

	*out = strdup(val->str);
	return CONFIG_OK;
}

static int config_iterator_next(config_value_t *it, config_value_t **val)
{
	lua_State *L;

	if (!it || !it->L || !val)
		return CONFIG_E_BADARGS;
	if (!is_iterator(it))
		return CONFIG_E_NON_MATCHING_TYPE;
	if (it->idx == -1)
		return CONFIG_NOMORE;

	L = it->L;

	if (!lua_istable(L, -1))
		return CONFIG_NOMORE;

	if (*val)
		config_free_value(*val);

	lua_pushinteger(L, it->idx);
	lua_gettable(L, -2);

	if (!lua_isnil(L, -1)) {
		generate_value_from_lua_stack(it->L, val);
		// lua_pop(L, 1);
		it->idx++;

		return CONFIG_OK;
	} else {
		it->idx = -1;
		return CONFIG_NOMORE;
	}
}

static void config_destroy_value(config_value_t **val)
{
	if (val && *val) {
		config_free_value(*val);
		mm_free(*val);
	}
}

static size_t config_get_challenges_list(config_t *c, list_head_t *h)
{
	size_t num_challenges = 0;
	config_value_t *it = NULL, *val = NULL;
	char *chall_name = NULL;

	if (config_get_value(c, &it, "challenges") != CONFIG_OK)
		goto end;

	if (config_is_string(it)) {
		config_get_as_string(it, &chall_name);
		list_push_back_noalloc(h, chall_name);
	} else {
		while (config_iterator_next(it, &val) == CONFIG_OK) {
			config_get_as_string(val, &chall_name);
			list_push_back_noalloc(h, chall_name);
		}
	}

	config_destroy_value(&val);
	config_destroy_value(&it);

	num_challenges = list_count(h);

end:
	return num_challenges;
}
#endif /* HAVE_LUA */

