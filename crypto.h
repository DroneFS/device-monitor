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

#include "crypto-private.h"
typedef struct fsroot_crypto_st fsroot_crypto_t;

void fsroot_crypto_init(fsroot_crypto_t *);
void fsroot_crypto_deinit(fsroot_crypto_t *);

void fsroot_crypto_set_logger(fsroot_crypto_t *, struct logger *);

int fsroot_crypto_load_challenge(fsroot_crypto_t *, const char *);
int fsroot_crypto_unload_challenge(fsroot_crypto_t *, const char *);

int fsroot_crypto_encrypt_with_challenges(fsroot_crypto_t *,
		const uint8_t *, size_t,
		uint8_t **, size_t *);
int fsroot_crypto_decrypt_with_challenges(fsroot_crypto_t *,
		const uint8_t *, size_t,
		uint8_t **, size_t *);

int fsroot_crypto_load_challenges_from_config(fsroot_crypto_t *, config_t *);
void fsroot_crypto_unload_all_challenges(fsroot_crypto_t *);

size_t fsroot_crypto_num_challenges_loaded(fsroot_crypto_t *);

#endif
