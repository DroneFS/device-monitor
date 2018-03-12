#include <string.h>
#include <malloc.h>

typedef unsigned char *PUCHAR;

int getNParams()
{
	return 0;
}

PUCHAR *getParamNames()
{
	return NULL;
}

/**
 * Ejecuta el challenge para proteger el fichero.
 *
 * Devuelve un array de punteros a cadenas de caracteres.
 * En la posición cero se encuentra la parte de la clave que ejecute la función.
 */
PUCHAR *executeParam()
{
	unsigned char *key, **params;
	const size_t keylen = 16;

	params = malloc(sizeof(unsigned char *) * 2);
	if (!params)
		return NULL;

	/* Devolvemos una cadena de 128 bits (16 bytes) de todo ceros */
	key = malloc(keylen);
	if (!key)
		return NULL;
	memset(key, 0, keylen);
	params[0] = key;

	/*
	 * El segundo puntero es nulo, ya que no tenemos
	 * parámetros de código en este challenge.
	 */
	params[1] = NULL;

	return params;
}

/**
 * Ejecuta el challenge para desproteger el fichero.
 *
 * En este ejemplo, ponemos 'paramsXml' siempre a NULL.
 *
 * Devuelve la parte de la clave para descifrar el fichero.
 */
PUCHAR execute(PUCHAR *paramsXml)
{
	unsigned char *key;
	const size_t keylen = 16;

	/* Devolvemos una cadena de 128 bits (16 bytes) de todo ceros */
	key = malloc(keylen);
	if (!key)
		return NULL;

	memset(key, 0, keylen);
	return key;
}

