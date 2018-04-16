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

static uint8_t *get_key_from_challenge(void *handle)
{
	uint8_t *key = NULL;
	unsigned char * (* func_execute)(unsigned char **);

	func_execute = dlsym(handle, "execute");
	if (func_execute)
		key = (uint8_t *) func_execute(NULL);

	return key;
}

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

static void memxor(uint8_t *dst, const uint8_t *src, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dst[i] = src[i] ^ dst[i];
}

static int fsroot_run_challenges(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_len,
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

	return f(fsc, in, in_len, key, keylen, iv, ivlen, out, out_len);
}

#define INITIAL_SLOTS 5

void crypto_init(crypto_t **fsc)
{
	crypto_t *fscp;

	if (fsc) {
		*fsc = mm_new0(crypto_t);
		fscp = *fsc;

		pthread_rwlock_init(&fscp->rwlock, NULL);

		fscp->num_challenges = 0;
		fscp->num_slots = INITIAL_SLOTS;
		fscp->challenges = mm_new(INITIAL_SLOTS, char *);
		fscp->handles = mm_new(INITIAL_SLOTS, void *);
		fscp->logger = NULL;

		fscp->algo.algo = ALGO_UNKNOWN;
		fscp->algo.keylen = KEYLEN_UNKNOWN;
		fscp->algo.mode = MODE_UNKNOWN;
	}
}

void crypto_deinit(crypto_t **fsc)
{
	crypto_t *fscp;

	if (fsc && *fsc) {
		fscp = *fsc;

		crypto_unload_all_challenges(fscp);

		fscp->num_challenges = 0;
		fscp->num_slots = 0;
		mm_free(fscp->challenges);
		mm_free(fscp->handles);

		pthread_rwlock_destroy(&fscp->rwlock);
		log_i(fscp->logger, "crypto: Deinitialized engine\n");

		*fsc = NULL;
	}
}

void crypto_set_logger(crypto_t *fsc, logger_t *logger)
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

static ssize_t get_expected_ciphertext_length(crypto_t *fsc, size_t in_len)
{
	ssize_t out_len = in_len;

	if (fsc->algo.mode == MODE_CBC)
		out_len += PADDING_LENGTH(in_len);
	else if (fsc->algo.mode != MODE_CTR)
		return CRYPTO_INVALID_MODE;

	return out_len;
}

ssize_t crypto_get_expected_output_length(crypto_t *fsc, size_t in_len)
{
	ssize_t ciphertext_len;

	if (!fsc)
		return E_BADARGS;

	/* This returns the length of the ciphertext only (without the IV) */
	ciphertext_len = get_expected_ciphertext_length(fsc, in_len);
	if (ciphertext_len <= 0)
		return ciphertext_len;

	/* Currently all IVs we use have a fixed length of 16 bytes (an AES block) */
	return AES_BLOCK_LENGTH + ciphertext_len;
}

int crypto_encrypt_with_challenges(crypto_t *fsc,
	const uint8_t *in, size_t in_len,
	uint8_t **out, size_t *out_len)
{
	char *algo;
	int retval = S_OK;
	uint8_t iv[AES_BLOCK_LENGTH];
	uint8_t *ciphertext_out;
	ssize_t ciphertext_len;

	if (!in || !in_len ||
		!out || !out_len)
		return E_BADARGS;

	if (fsc->algo.algo == ALGO_UNKNOWN ||
		fsc->algo.keylen == KEYLEN_UNKNOWN ||
		fsc->algo.mode == MODE_UNKNOWN)
		return E_NOTINITIALIZED;

	if (crypto_num_challenges_loaded(fsc) == 0)
		return E_EMPTY;

	/* Generate a random IV of the same length as the AES block size */
	if (get_random_bytes(iv, sizeof(iv)) < sizeof(iv))
		return E_SYSCALL;

	if ((ciphertext_len = get_expected_ciphertext_length(fsc, in_len)) < 0)
		return ciphertext_len;

	/* We return a blob with the IV + the ciphertext */
	ciphertext_out = mm_malloc0(sizeof(iv) + ciphertext_len);

	algo = crypto_get_algorithm_description(fsc, "<unknown>");
	log_i(fsc->logger, "Encrypting a file of length %zu bytes (algo: %s)\n", in_len, algo);
	mm_free(algo);

	/* Run the challenges and generate the ciphertext */
	pthread_rwlock_rdlock(&fsc->rwlock);
	retval = fsroot_run_challenges(fsc, in, in_len,
			ciphertext_out + sizeof(iv), ciphertext_len,
			iv, sizeof(iv),
			encrypt_internal);
	pthread_rwlock_unlock(&fsc->rwlock);

	if (retval != S_OK) {
		mm_free(ciphertext_out);
		log_e(fsc->logger, "Encryption failed\n");
	} else {
		memcpy(ciphertext_out, iv, sizeof(iv));
		*out = ciphertext_out;
		*out_len = sizeof(iv) + ciphertext_len;
	}

	return retval;
}

int crypto_encrypt_with_challenges2(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_len)
{
	int retval;
	char *algo;
	ssize_t expected_len;
	uint8_t iv[AES_BLOCK_LENGTH];

	if (!fsc || !in || !out)
		return E_BADARGS;

	if (fsc->algo.algo == ALGO_UNKNOWN ||
		fsc->algo.keylen == KEYLEN_UNKNOWN ||
		fsc->algo.mode == MODE_UNKNOWN)
		return E_NOTINITIALIZED;

	expected_len = crypto_get_expected_output_length(fsc, in_len);
	if (expected_len < 0)
		return expected_len;
	if (expected_len > (ssize_t) out_len)
		return E_NOMEM;

	/* Generate a random IV of the same length as the AES block size */
	if (get_random_bytes(iv, sizeof(iv)) < sizeof(iv))
		return E_SYSCALL;

	algo = crypto_get_algorithm_description(fsc, "<unknown>");
	log_i(fsc->logger, "Encrypting a file of length %zu bytes (inline) (algo: %s)\n", in_len, algo);
	mm_free(algo);

	memcpy(out, iv, sizeof(iv));
	out += sizeof(iv);
	out_len -= sizeof(iv);

	pthread_rwlock_rdlock(&fsc->rwlock);
	retval = fsroot_run_challenges(fsc, in, in_len,
			out + sizeof(iv), out_len,
			iv, sizeof(iv),
			encrypt_internal);
	pthread_rwlock_unlock(&fsc->rwlock);

	if (retval != S_OK)
		log_e(fsc->logger, "Encryption failed (inline)\n");

	return retval;
}

int crypto_decrypt_with_challenges(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len)
{
	int retval;
	char *algo;
	/* IV comes first */
	const uint8_t *iv = in;
	size_t ivlen = AES_BLOCK_LENGTH;
	uint8_t *plaintext_out;

	if (!fsc || !in || !out || !out_len)
		return E_BADARGS;
	if (in_len <= ivlen)
		return E_BADARGS;

	/* Check the algorithm has been properly initialized */
	if (fsc->algo.algo == ALGO_UNKNOWN ||
		fsc->algo.keylen == KEYLEN_UNKNOWN ||
		fsc->algo.mode == MODE_UNKNOWN)
		return E_NOTINITIALIZED;

	/* Ciphertext comes right after IV */
	in += ivlen;
	in_len -= ivlen;

	algo = crypto_get_algorithm_description(fsc, "<unknown>");
	log_i(fsc->logger, "Decrypting a file of length %zu bytes (algo: %s)\n", in_len, algo);
	mm_free(algo);

	plaintext_out = mm_malloc0(in_len);

	pthread_rwlock_rdlock(&fsc->rwlock);
	retval = fsroot_run_challenges(fsc, in, in_len,
			plaintext_out, in_len,
			iv, ivlen,
			decrypt_internal);
	pthread_rwlock_unlock(&fsc->rwlock);

	if (retval != S_OK) {
		mm_free(plaintext_out);
		log_e(fsc->logger, "Decryption failed\n");
	} else {
		*out_len = in_len;
		*out = plaintext_out;
	}

	return retval;
}

int crypto_decrypt_with_challenges2(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_len)
{
	int retval;
	char *algo;
	const uint8_t *iv = in;
	size_t ivlen = AES_BLOCK_LENGTH;

	if (!fsc || !in || !out)
		return E_BADARGS;
	if (in_len < ivlen)
		return E_BADARGS;

	/* Check the algorithm has been properly initialized */
	if (fsc->algo.algo == ALGO_UNKNOWN ||
		fsc->algo.keylen == KEYLEN_UNKNOWN ||
		fsc->algo.mode == MODE_UNKNOWN)
		return E_NOTINITIALIZED;

	in += ivlen;
	in_len -= ivlen;

	if (out_len < in_len)
		return E_NOMEM;

	algo = crypto_get_algorithm_description(fsc, "<unknown>");
	log_i(fsc->logger, "Decrypting a file of length %zu bytes (inline) (algo: %s)\n", in_len, algo);
	mm_free(algo);

	pthread_rwlock_rdlock(&fsc->rwlock);
	retval = fsroot_run_challenges(fsc, in, in_len,
			out, out_len,
			iv, ivlen,
			decrypt_internal);
	pthread_rwlock_unlock(&fsc->rwlock);

	if (retval != S_OK)
		log_e(fsc->logger, "Decryption failed (inline)\n");

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
	int retval = S_OK;
	list_head_t h;

	if (!fsc || !c)
		return E_BADARGS;

	list_init(&h);

	if (c->get_challenges_list(c, &h) > 0) {
		for (struct list_node_st *cur_node = h.first;
				cur_node;
				cur_node = cur_node->next) {
			log_i(fsc->logger, "Loading challenge '%s'\n",
					(const char *) cur_node->value);
			retval = crypto_load_challenge(fsc, cur_node->value);
			if (retval != S_OK) {
				log_e(fsc->logger, "Could not load challenge '%s'\n",
					(const char *) cur_node->value);
				break;
			}
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
