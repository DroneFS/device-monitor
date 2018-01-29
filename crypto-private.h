/*
 * crypto-private.h
 *
 *  Created on: Jan 29, 2018
 *      Author: aja
 */

#ifndef CRYPTO_PRIVATE_H_
#define CRYPTO_PRIVATE_H_
#include <pthread.h>

struct fsroot_crypto_st
{
	pthread_rwlock_t rwlock;
	size_t num_challenges;
	size_t num_slots;
	char **challenges;
	void **handles;
	struct logger *logger;
};

#endif /* CRYPTO_PRIVATE_H_ */
