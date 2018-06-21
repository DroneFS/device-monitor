/*
 * crypto.h
 *
 *  Created on: 15 Sep 2017
 *      Author: Ander Juaristi
 */
#ifndef __CRYPTO_H__
#define __CRYPTO_H__
#include <stdint.h>
#include "log.h"

#include "configuration.h"
#include "formatter.h"

/* Return values */
#define CRYPTO_OK 			 	 0
#define CRYPTO_INVALID_ALGORITHM		-1
#define CRYPTO_INVALID_KEY_LEN			-2
#define CRYPTO_INVALID_MODE			-3
#define CRYPTO_INVALID_IV_LEN			-4
#define CRYPTO_UNKNOWN_ERROR			-5
#define CRYPTO_CHALL_UNIMPLEMENTED_FUNCTION	-6
#define CRYPTO_CHALL_ERROR			-7

typedef enum {
	ACTION_ENCRYPT,
	ACTION_DECRYPT
} cipher_action_t;

typedef struct crypto_st crypto_t;

struct chall_ctx
{
	uint8_t *key;
	uint8_t key_length;
	uint16_t n_params;
	unsigned char **param_names;
	unsigned char **params;
};

void crypto_init(crypto_t **);
void crypto_deinit(crypto_t **);

void crypto_set_logger(crypto_t *, logger_t *);
int crypto_set_algorithm(crypto_t *, const char *);

char *crypto_get_algorithm_description(crypto_t *, const char *);

int crypto_load_challenge(crypto_t *, const char *);
int crypto_unload_challenge(crypto_t *, const char *);

uint8_t *crypto_create_plaintext_buffer(crypto_t *, size_t *);

int crypto_encrypt_with_challenges(crypto_t *, file_formatter_t *,
		const uint8_t *, size_t,
		uint8_t **, size_t *);
int crypto_encrypt_with_challenges2(crypto_t *, file_formatter_t *,
		const uint8_t *, size_t,
		uint8_t *, size_t);

int crypto_decrypt_with_challenges(crypto_t *, file_reader_t *,
		const uint8_t *, size_t,
		uint8_t *, size_t);

int crypto_load_challenges_from_config(crypto_t *, config_t *);
void crypto_unload_all_challenges(crypto_t *);

size_t crypto_num_challenges_loaded(crypto_t *);

#endif

