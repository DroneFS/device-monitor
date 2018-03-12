/*
 * crypto.c
 *
 *  Created on: 12 Sep 2017
 *      Author: Ander Juaristi
 */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <dlfcn.h>
#include "crypto.h"
#include "crypto-internal.h"
#include "mm.h"
#include "return-codes.h"

static size_t get_random_bytes(uint8_t *dst, size_t len)
{
	size_t read_bytes = 0;
	FILE *fp = fopen("/dev/urandom", "r");

	if (fp) {
		read_bytes = fread(dst, 1, len, fp);
		fclose(fp);
	}

	return read_bytes;
}

static int load_challenge(crypto_t *fsc, const char *libch, unsigned int index)
{
	void *handle = dlopen(libch, RTLD_NOW);

	if (!handle) {
		log_e(fsc->logger, "Could not load challenge '%s'\n", libch);
		return E_SYSCALL;
	}

	/* Library was loaded successfully - copy handle and name in the structure */
	fsc->challenges[index] = strdup(libch);
	fsc->handles[index] = handle;
	log_i(fsc->logger, "Challenge loaded: %s\n", libch);
	return S_OK;
}

static void unload_challenge(crypto_t *fsc, unsigned int index)
{
	/* Unload the challenge at the designated index */
	log_i(fsc->logger, "Unloading challenge: %s\n", fsc->challenges[index]);

	mm_free(fsc->challenges[index]);
	dlclose(fsc->handles[index]);

	fsc->challenges[index] = NULL;
	fsc->handles[index] = NULL;
}

static uint8_t *get_key_from_challenge(void *handle)
{
	uint8_t *key = NULL;
	unsigned char * (* func_execute)(unsigned char **);

	func_execute = dlsym(handle, "execute");
	if (func_execute)
		key = (uint8_t *) func_execute(NULL);

	return key;
}

static void memxor(uint8_t *dst, const uint8_t *src, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dst[i] = src[i] ^ dst[i];
}

static int fsroot_run_challenges(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len,
		const uint8_t *iv, size_t ivlen,
		fsroot_cipher_func_t f)
{
	const size_t keylen = AES_KEY_LENGTH;
	uint8_t key[keylen], *tmp_key = NULL;

	/* Initialize key to zero */
	memset(key, 0, keylen);

	/* Walk over the list of challenges */
	for (size_t i = 0; i < fsc->num_challenges; i++) {
		if (fsc->challenges[i]) {
			tmp_key = get_key_from_challenge(fsc->handles[i]);
			if (!tmp_key) {
				log_e(fsc->logger, "Could not get key from challenge %s\n",
						fsc->challenges[i]);
				return E_UNKNOWN;
			}

			/* key is a 128 bit (16 bytes) value */
			memxor(key, tmp_key, keylen);
			mm_free(tmp_key);

			log_i(fsc->logger, "Got key from challenge %s\n", fsc->challenges[i]);
		}
	}

	return f(in, in_len, out, out_len, key, keylen, iv, ivlen);
}

#define INITIAL_SLOTS 5

void crypto_init(crypto_t *fsc)
{
	pthread_rwlock_init(&fsc->rwlock, NULL);
	fsc->num_challenges = 0;
	fsc->num_slots = INITIAL_SLOTS;
	fsc->challenges = mm_new(INITIAL_SLOTS, char *);
	fsc->handles = mm_new(INITIAL_SLOTS, void *);
	fsc->logger = NULL;
}

void crypto_deinit(crypto_t *fsc)
{
	crypto_unload_all_challenges(fsc);

	fsc->num_challenges = 0;
	fsc->num_slots = 0;
	mm_free(fsc->challenges);
	mm_free(fsc->handles);

	pthread_rwlock_destroy(&fsc->rwlock);
	log_i(fsc->logger, "crypto: Deinitialized engine\n");
}

void crypto_set_logger(crypto_t *fsc, struct logger *logger)
{
	if (fsc)
		fsc->logger = logger;
}

static void resize_slots(crypto_t *fsc)
{
	size_t num_slots = fsc->num_slots << 1;
	mm_realloc(fsc->challenges, num_slots);
	mm_realloc(fsc->handles, num_slots);
	fsc->num_slots = num_slots;
}

int crypto_load_challenge(crypto_t *fsc, const char *libch)
{
	/* 'FSROOT_E_NOMEM' means we reached the maximum number challenges allowed (currently 5) */
	int retval = E_NOMEM;

	if (!fsc || !libch || !*libch)
		return E_BADARGS;

	pthread_rwlock_wrlock(&fsc->rwlock);

	if (fsc->num_challenges == SIZE_MAX) {
		pthread_rwlock_unlock(&fsc->rwlock);
		return E_NOMEM;
	}

	if (fsc->num_slots == fsc->num_challenges) {
		if ((fsc->num_slots + 1) >= SIZE_MAX) {
			pthread_rwlock_unlock(&fsc->rwlock);
			return E_NOMEM;
		}
		resize_slots(fsc);
	}

	for (size_t i = 0; i < fsc->num_slots; i++) {
		if (fsc->challenges[i] && strcmp(fsc->challenges[i], libch) == 0) {
			/* This challenge is already loaded */
			retval = S_OK;
			break;
		} else if (fsc->challenges[i] == NULL) {
			/* We load this challenge at the designated index */
			retval = load_challenge(fsc, libch, i);
			if (retval == S_OK)
				fsc->num_challenges++;
			break;
		}
	}

	pthread_rwlock_unlock(&fsc->rwlock);

	return retval;
}

int crypto_unload_challenge(crypto_t *fsc, const char *libch)
{
	int retval = E_NOTFOUND;

	pthread_rwlock_wrlock(&fsc->rwlock);

	for (size_t i = 0; i < fsc->num_slots; i++) {
		if (fsc->challenges[i] && strcmp(fsc->challenges[i], libch) == 0) {
			unload_challenge(fsc, i);
			fsc->num_challenges--;
			retval = S_OK;
			break;
		}
	}

	pthread_rwlock_unlock(&fsc->rwlock);
	return retval;
}

int crypto_encrypt_with_challenges(crypto_t *fsc,
	const uint8_t *in, size_t in_len,
	uint8_t **out, size_t *out_len)
{
	int retval = S_OK;
	uint8_t iv[AES_BLOCK_LENGTH];
	uint8_t *ciphertext_out;
	size_t ciphertext_len;

	if (!in || !in_len ||
		!out || !out_len)
		return E_BADARGS;

	/* Generate a random IV of the same length as the AES block size */
	if (get_random_bytes(iv, sizeof(iv)) < sizeof(iv))
		return E_SYSCALL;

	log_i(fsc->logger, "Encrypting a file of length %lu bytes\n", in_len);

	pthread_rwlock_rdlock(&fsc->rwlock);
	retval = fsroot_run_challenges(fsc, in, in_len,
			&ciphertext_out, &ciphertext_len,
			iv, sizeof(iv),
			encrypt_internal);
	pthread_rwlock_unlock(&fsc->rwlock);
	if (retval != S_OK) {
		log_e(fsc->logger, "Encryption failed\n");
		goto end;
	}

	/* Return a blob with the IV + the ciphertext */
	*out_len = sizeof(iv) + ciphertext_len;
	*out = mm_malloc0(*out_len);
	memcpy(*out, iv, sizeof(iv));
	memcpy((*out) + sizeof(iv), ciphertext_out, ciphertext_len);
	mm_free(ciphertext_out);

end:
	return retval;
}

int crypto_decrypt_with_challenges(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len)
{
	int retval;
	/* IV comes first */
	const uint8_t *iv = in;
	size_t ivlen = AES_BLOCK_LENGTH;

	/* Ciphertext comes right after IV */
	in += ivlen;
	in_len -= ivlen;

	log_i(fsc->logger, "Decrypting a file of length %lu bytes\n", in_len);

	pthread_rwlock_rdlock(&fsc->rwlock);
	retval = fsroot_run_challenges(fsc, in, in_len,
			out, out_len,
			iv, ivlen,
			decrypt_internal);
	pthread_rwlock_unlock(&fsc->rwlock);

	if (retval != S_OK)
		log_e(fsc->logger, "Decryption failed\n");

	return retval;
}

/**
 * \param[in] fsc
 * \return The number of challenges loaded
 */
size_t crypto_num_challenges_loaded(crypto_t *fsc)
{
	int retval;

	pthread_rwlock_rdlock(&fsc->rwlock);
	retval = (fsc ? fsc->num_challenges : 0);
	pthread_rwlock_unlock(&fsc->rwlock);

	return retval;
}

/**
 * \param[in] fsc
 * \param[in] c
 * \return The number of challenges loaded, or negative value on error
 */
int crypto_load_challenges_from_config(crypto_t *fsc, config_t *c)
{
	int retval;
	list_head_t h;

	if (!fsc || !c)
		return E_BADARGS;

	list_init(&h);

	if (c->get_challenges_list(c, &h) > 0) {
		for (struct list_node_st *cur_node = h.first;
				cur_node;
				cur_node = cur_node->next) {
			retval = crypto_load_challenge(fsc, cur_node->value);
			if (retval != S_OK)
				break;
		}
	}

	list_destroy(&h, NULL);

	if (retval == S_OK) {
		pthread_rwlock_rdlock(&fsc->rwlock);
		retval = (fsc->num_challenges >= INT_MAX ?
				INT_MAX :
				fsc->num_challenges);
		pthread_rwlock_unlock(&fsc->rwlock);

	}

	return retval;
}

/**
 * \param[in] fsc
 */
void crypto_unload_all_challenges(crypto_t *fsc)
{
	pthread_rwlock_wrlock(&fsc->rwlock);
	if (fsc->num_challenges > 0) {
		for (size_t i = 0; i < fsc->num_challenges; i++)
			unload_challenge(fsc, i);
		fsc->num_challenges = 0;
	}
	pthread_rwlock_unlock(&fsc->rwlock);
}
