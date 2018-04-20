/*
 * chall.c
 *
 *  Created on: Apr 20, 2018
 *      Author: Ander Juaristi
 */
#include <dlfcn.h>
#include <string.h>
#include "mm.h"
#include "crypto.h"
#include "return-codes.h"

typedef unsigned char *PUCHAR;

static int call_execute_param(void *handle, struct chall_ctx *cctx)
{
	unsigned char *param;
	PUCHAR *retvals;
	PUCHAR * (* func_execute_param) (void);

	func_execute_param = dlsym(handle, "executeParam");
	if (!func_execute_param)
		return CRYPTO_CHALL_UNIMPLEMENTED_FUNCTION;

	/* Invoke the challenge */
	retvals = func_execute_param();
	if (!retvals)
		return CRYPTO_CHALL_ERROR;

	/* First return value is the key */
	memcpy(cctx->key, retvals[0], cctx->key_length);
	mm_free(retvals[0]);

	/* Subsequent values are the parameters */
	for (unsigned i = 0; i < cctx->n_params; i++) {
		param = retvals[i + 1];

		if (param)
			cctx->params[i] = (unsigned char *) strdup((const char *) param);
		else
			return CRYPTO_CHALL_ERROR;

		mm_free(param);
	}

	return CRYPTO_OK;
}

static int call_execute(void *handle, struct chall_ctx *cctx)
{
	uint8_t *key = NULL;
	PUCHAR (* func_execute) (PUCHAR *);

	func_execute = dlsym(handle, "execute");
	if (!func_execute)
		return CRYPTO_CHALL_UNIMPLEMENTED_FUNCTION;

	key = func_execute(cctx->params);
	if (!key)
		return CRYPTO_CHALL_ERROR;

	memcpy(cctx->key, key, cctx->key_length);
	mm_free(key);

	return 0;
}

static int call_get_n_params(void *handle)
{
	int (* get_n_params) (void);

	get_n_params = dlsym(handle, "getNParams");
	if (!get_n_params)
		return CRYPTO_CHALL_UNIMPLEMENTED_FUNCTION;

	return get_n_params();
}

static int call_get_param_names(void *handle, struct chall_ctx *cctx)
{
	PUCHAR *retvals;
	PUCHAR * (* func_get_param_names) (void);

	if (!cctx->n_params)
		return 0;

	func_get_param_names = dlsym(handle, "getParamNames");
	if (!func_get_param_names)
		return CRYPTO_CHALL_UNIMPLEMENTED_FUNCTION;

	retvals = func_get_param_names();
	if (!retvals)
		return CRYPTO_CHALL_ERROR;

	for (int i = 0; i < cctx->n_params; i++) {
		if (retvals[i])
			cctx->param_names[i] = (unsigned char *) strdup((const char *) retvals[i]);
		else
			return CRYPTO_CHALL_ERROR;

		mm_free(retvals[i]);
	}

	return 0;
}

int chall_run(void *handle, struct chall_ctx *cctx, cipher_action_t action)
{
	int n_params, retval = 0;

	if (!handle || !cctx)
		return E_BADARGS;

	if (action == ACTION_ENCRYPT) {
		/* How many params does this challenge have? */
		n_params = call_get_n_params(handle);
		if (n_params < 0)
			return n_params;

		/* Allocate memory for all the params */
		cctx->n_params = n_params;
		cctx->params = NULL;

		if (cctx->n_params > 0) {
			cctx->params = mm_new(cctx->n_params, char *);
			cctx->param_names = mm_new(cctx->n_params, char *);

			/* Retrieve the param names */
			retval = call_get_param_names(handle, cctx);
		}

		if (retval < 0)
			goto end;

		/* Run the challenge */
		retval = call_execute_param(handle, cctx);
	} else if (action == ACTION_DECRYPT) {
		retval = call_execute(handle, cctx);
	} else {
		return CRYPTO_INVALID_ALGORITHM;
	}

end:
	if (retval < 0) {
		mm_free(cctx->key);
		cctx->key_length = 0;

		for (unsigned i = 0; i < cctx->n_params; i++) {
			mm_free(cctx->params[i]);
			mm_free(cctx->param_names[i]);
		}

		mm_free(cctx->params);
		mm_free(cctx->param_names);
		cctx->n_params = 0;
	}

	return retval;
}
