/*
 * fsroot-crypto.h
 *
 *  Created on: 15 Sep 2017
 *      Author: Ander Juaristi
 */
#ifndef __FSROOT_CRYPTO_H__
#define __FSROOT_CRYPTO_H__
#include <stdint.h>

struct fsroot_crypto_st
{
	size_t num_challenges;
	size_t num_slots;
	char **challenges;
	void **handles;
};
typedef struct fsroot_crypto_st fsroot_crypto_t;

void fsroot_crypto_init(fsroot_crypto_t *);
void fsroot_crypto_deinit(fsroot_crypto_t *);

int fsroot_crypto_load_challenge(fsroot_crypto_t *, const char *);
int fsroot_crypto_unload_challenge(fsroot_crypto_t *, const char *);

int fsroot_crypto_encrypt_with_challenges(fsroot_crypto_t *,
		const uint8_t *, size_t,
		uint8_t **, size_t *);
int fsroot_crypto_decrypt_with_challenges(fsroot_crypto_t *,
		const uint8_t *, size_t,
		uint8_t **, size_t *);

#endif

