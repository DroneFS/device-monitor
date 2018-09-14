#include <string.h>
#include <malloc.h>

typedef unsigned char *PUCHAR;

int read_alt ()
{
    FILE* file = fopen ("/home/pi/Desktop/hola.txt", "r");
    int i = 0;
    fscanf (file, "%d", &i); 
    fclose (file); 
	return i;
}

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
    int resul = read_alt();

    int alt0 = 0;
    int cuanto = 2;
    resul = (resul-alt0)/cuanto;

	params = malloc(sizeof(unsigned char *) * 2);
	if (!params)
		return NULL;

	/* Devolvemos una cadena de 128 bits (16 bytes) de todo ceros */
	key = malloc(keylen);
	if (!key)
		return NULL;
	memset(key, resul, keylen);
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
    int resul = read_alt();

    int alt0 = 0;
    int cuanto = 2;
    resul = (resul-alt0)/cuanto;

	/* Devolvemos una cadena de 128 bits (16 bytes) de todo ceros */
	key = malloc(keylen);
	if (!key)
		return NULL;

	memset(key, resul, keylen);
	return key;
}

