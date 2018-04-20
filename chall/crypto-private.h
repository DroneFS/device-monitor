/*
 * crypto-private.h
 *
 *  Created on: Jan 29, 2018
 *      Author: aja
 */

#ifndef CRYPTO_PRIVATE_H_
#define CRYPTO_PRIVATE_H_
#include <pthread.h>

#define ALGO_UNKNOWN	0
#define ALGO_AES	1

#define KEYLEN_UNKNOWN	0

enum block_cipher_mode {
	MODE_UNKNOWN = 0,
	MODE_CBC,
	MODE_CTR
};

struct crypto_st
{
	pthread_rwlock_t rwlock;
	size_t num_challenges;
	size_t num_slots;
	char **challenges;
	void **handles;
	logger_t *logger;

	struct {
		unsigned int algo;
		unsigned int keylen;
		unsigned int keylen_bytes;
		enum block_cipher_mode mode;
	} algo;
};

#endif /* CRYPTO_PRIVATE_H_ */
