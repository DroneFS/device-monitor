/*
 * crypto-internal.h
 *
 *  Created on: Nov 29, 2017
 *      Author: aja
 */

#ifndef CRYPTO_INTERNAL_H_
#define CRYPTO_INTERNAL_H_
#include <stdint.h>
#include "crypto-private.h"

#define AES_KEY_LENGTH 16
#define AES_BLOCK_LENGTH 16

typedef int (* fsroot_cipher_func_t)(const uint8_t *, size_t,	/* Input */
		uint8_t **, size_t *,				/* Output */
		uint8_t *, size_t,				/* Key */
		const uint8_t *, size_t);			/* IV */

#define PADDING_LENGTH(in_len) \
	(AES_BLOCK_LENGTH - (in_len % AES_BLOCK_LENGTH))

int encrypt_internal(const uint8_t *, size_t,
		uint8_t **, size_t *,
		uint8_t *, size_t,
		const uint8_t *, size_t);

int decrypt_internal(const uint8_t *, size_t,
		uint8_t **, size_t *,
		uint8_t *, size_t,
		const uint8_t *, size_t);

#endif /* CRYPTO_INTERNAL_H_ */
