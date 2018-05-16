/*
 * crypto-algo.c
 *
 *  Created on: Mar 12, 2018
 *      Author: aja
 */
#include <stdio.h>
#include <string.h>
#include "mm.h"
#include "crypto.h"
#include "crypto-private.h"

static const char *check_algo(crypto_t *fsc, const char *start)
{
	if (strncmp(start, "AES", 3))
		return NULL;

	start += 3;
	if (*start++ != '-')
		return NULL;

	fsc->algo.algo = ALGO_AES;
	return start;
}

static const char *check_keylen(crypto_t *fsc, const char *start)
{
	if (strncmp(start, "128", 3) == 0)
		fsc->algo.keylen = 128;
	else if (strncmp(start, "192", 3) == 0)
		fsc->algo.keylen = 192;
	else if (strncmp(start, "256", 3) == 0)
		fsc->algo.keylen = 256;
	else
		return NULL;

	start += 3;
	if (*start++ != '-')
		return NULL;

	fsc->algo.keylen_bytes = fsc->algo.keylen / 8;

	return start;
}

static const char *check_mode(crypto_t *fsc, const char *start)
{
	if (strncmp(start, "CTR", 3) == 0)
		fsc->algo.mode = MODE_CTR;
	else if (strncmp(start, "CBC", 3) == 0)
		fsc->algo.mode = MODE_CBC;
	else
		return NULL;

	return start;
}

int crypto_set_algorithm(crypto_t *fsc, const char *algo)
{
	int retval = CRYPTO_INVALID_ALGORITHM;
	const char *start = algo;

	start = check_algo(fsc, start);
	if (!start)
		goto end;

	start = check_keylen(fsc, start);
	if (!start)
		goto end;

	start = check_mode(fsc, start);
	if (!start)
		goto end;

	if (fsc->algo.algo == ALGO_UNKNOWN ||
			fsc->algo.keylen == KEYLEN_UNKNOWN ||
			fsc->algo.mode == MODE_UNKNOWN)
		return CRYPTO_INVALID_ALGORITHM;

	retval = CRYPTO_OK;

end:
	return retval;
}

char *crypto_get_algorithm_description(crypto_t *fsc, const char *default_desc)
{
	char *algo = NULL, *mode;
	size_t len = 3 + 3 + 3 + 2 + 1;

	if (fsc->algo.algo == ALGO_UNKNOWN)
		goto end;
	if (fsc->algo.keylen != 128 &&
			fsc->algo.keylen != 192 &&
			fsc->algo.keylen != 256)
		goto end;

	switch (fsc->algo.mode) {
	case MODE_CTR:
		mode = "CTR";
		break;
	case MODE_CBC:
		mode = "CBC";
		break;
	default:
		goto end;
	}

	algo = mm_malloc0(len);
	snprintf(algo, len, "AES-%d-%s",
			fsc->algo.keylen,
			mode);

end:
	if (algo == NULL && default_desc)
		algo = strdup("<unknown>");

	return algo;
}
