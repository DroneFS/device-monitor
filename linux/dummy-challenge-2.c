#include <string.h>
#include <malloc.h>

#define N_PARAMS 2

typedef unsigned char *PUCHAR;

int getNParams()
{
	return N_PARAMS;
}

PUCHAR *getParamNames()
{
	unsigned char **names = malloc(sizeof(unsigned char *) * N_PARAMS);
	if (names) {
		names[0] = (unsigned char *) strdup("param-1");
		names[1] = (unsigned char *) strdup("param-2");
	}
	return names;
}

PUCHAR *executeParam()
{
	unsigned char *key, **params;
	const size_t keylen = 16;

	key = malloc(keylen);
	if (!key)
		return NULL;

	params = malloc(sizeof(unsigned char *) * 3);
	if (!params) {
		free(key);
		return NULL;
	}

	params[1] = (unsigned char *) strdup("aja");
	params[2] = (unsigned char *) strdup("AJA");

	memset(key, 0, keylen);
	params[0] = key;

	memcpy(key, params[1], 3);
	memcpy(key + keylen - 3, params[2], 3);

	return params;
}

PUCHAR execute(PUCHAR *paramsXml)
{
	unsigned char *key;
	const size_t keylen = 16;

	if (!paramsXml)
		return NULL;

	key = malloc(keylen);
	if (!key)
		return NULL;

	memset(key, 0, keylen);

	/* Walk over the params */
	for (unsigned i = 0; i < N_PARAMS; i++) {
		if (!paramsXml[i]) {
			free(key);
			key = NULL;
			break;
		}

		if (i == 0)
			memcpy(key, paramsXml[i], 3);
		else if (i == 1)
			memcpy(key + keylen - 3, paramsXml[i], 3);
	}

	return key;
}
