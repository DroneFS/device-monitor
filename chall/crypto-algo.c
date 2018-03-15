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

static int check_algo(crypto_t *fsc, const char *start)
{
	if (strncmp(start, "AES", 3))
		return CRYPTO_INVALID_ALGORITHM;

	fsc->algo.algo = ALGO_AES;
	return 0;
}

static int check_keylen(crypto_t *fsc, const char *start)
{
	if (strncmp(start, "128", 3) == 0)
		fsc->algo.keylen = 128;
	else if (strncmp(start, "192", 3) == 0)
		fsc->algo.keylen = 192;
	else if (strncmp(start, "256", 3) == 0)
		fsc->algo.keylen = 256;
	else
		return CRYPTO_INVALID_KEY_LEN;

	return 0;
}

static int check_mode(crypto_t *fsc, const char *start)
{
	if (strncmp(start, "CTR", 3) == 0)
		fsc->algo.mode = MODE_CTR;
	else if (strncmp(start, "CBC", 3) == 0)
		fsc->algo.mode = MODE_CBC;
	else
		return CRYPTO_INVALID_MODE;

	return 0;
}

int crypto_set_algorithm(crypto_t *fsc, const char *algo)
{
	int retval = 0;
	char *pos = NULL;
	const char *start = algo;
	enum states {
		STATE_ALGO,
		STATE_KEYLEN,
		STATE_MODE
	} state = STATE_ALGO;

	while (strtok_r((char *) start, "-", &pos)) {
		switch (state) {
		case STATE_ALGO:
			retval = check_algo(fsc, start);
			if (retval)
				goto end;

			start = pos;
			state = STATE_KEYLEN;
			break;
		case STATE_KEYLEN:
			retval = check_keylen(fsc, start);
			if (retval)
				goto end;

			start = pos;
			state = STATE_MODE;
			break;
		case STATE_MODE:
			retval = check_mode(fsc, start);
			if (retval)
				goto end;

			goto check;
			break;
		}
	}

check:
	if (fsc->algo.algo == ALGO_UNKNOWN ||
			fsc->algo.keylen == KEYLEN_UNKNOWN ||
			fsc->algo.mode == MODE_UNKNOWN)
		return CRYPTO_INVALID_ALGORITHM;

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
