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

static void memxor(uint8_t *dst, const uint8_t *src, size_t len)
{
	for (size_t i = 0; i < len; i++)
		dst[i] = src[i] ^ dst[i];
}

static int fsroot_run_challenges_for_encryption(crypto_t *fsc,
		file_formatter_t *fmt,
		const uint8_t *in, size_t in_len,
		const uint8_t *iv, size_t ivlen,
		uint8_t *out, size_t out_len)
{
	void *ch;
	int retval;
	struct chall_ctx cctx;
	const size_t keylen = fsc->algo.keylen_bytes;
	uint8_t key[keylen];

	memset(key, 0, keylen);
	memset(&cctx, 0, sizeof(struct chall_ctx));

	if (fmt->set_init_vector(fmt, iv, ivlen) != S_OK)
		return CRYPTO_UNKNOWN_ERROR;

	/* Generate the challenge context */
	cctx.key_length = keylen;
	cctx.key = mm_malloc0(keylen);

	/* Walk over the list of challenges */
	for (size_t i = 0; i < fsc->num_challenges; i++) {
		if (fsc->challenges[i]) {
			retval = chall_run(fsc->handles[i], &cctx, ACTION_ENCRYPT);

			if (retval != CRYPTO_OK) {
				log_e(fsc->logger, "[ENCR] Could not get key from challenge %s\n",
						fsc->challenges[i]);

				mm_free(cctx.key);
				cctx.key_length = 0;

				return E_UNKNOWN;
			}

			memxor(key, cctx.key, keylen);
			memset(cctx.key, 0, keylen);

			log_i(fsc->logger, "[ENCR] Got key from challenge %s\n", fsc->challenges[i]);

			ch = fmt->challenge_start(fmt, fsc->challenges[i]);

			/* Post the received parameters */
			for (uint16_t pi = 0; pi < cctx.n_params; pi++) {
				if (cctx.param_names[pi] && cctx.params[pi]) {
					fmt->set_param(ch,
							(const char *) cctx.param_names[pi],
							(const char *) cctx.params[pi]);
				}
			}

			fmt->challenge_end(fmt, ch);
		}
	}

	/* Destroy the secret key so that consumers don't have access to it */
	mm_free(cctx.key);
	cctx.key_length = 0;

	/* Free params and param names */
	for (int i = 0; i < cctx.n_params; i++) {
		mm_free(cctx.params[i]);
		mm_free(cctx.param_names[i]);
	}

	mm_free(cctx.params);
	mm_free(cctx.param_names);

	return encrypt_internal(fsc, in, in_len, key, keylen, iv, ivlen, out, out_len);
}

static int chall_get_params(file_reader_t *r, void *ch, struct chall_ctx *cctx)
{
	int num_params;

	cctx->n_params = 0;
	cctx->params = NULL;
	cctx->param_names = NULL;

	num_params = r->get_num_params(ch);
	if (num_params > 0) {
		cctx->n_params = num_params;
		cctx->params = mm_new(cctx->n_params, char *);
		cctx->param_names = mm_new(cctx->n_params, char *);

		for (unsigned i = 0; i < cctx->n_params; i++) {
			if (r->get_param(ch, i,
					&cctx->param_names[i],
					&cctx->params[i]) != S_OK)
				return CRYPTO_CHALL_ERROR;
		}
	}

	return num_params >= 0 ? 0 : num_params;
}

static void chall_free_params(struct chall_ctx *cctx)
{
	for (int i = 0; i < cctx->n_params; i++) {
		mm_free(cctx->params[i]);
		mm_free(cctx->param_names[i]);
	}

	mm_free(cctx->params);
	mm_free(cctx->param_names);
	cctx->n_params = 0;
}

static int fsroot_run_challenges_for_decryption(crypto_t *fsc,
		file_reader_t *r,
		const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_len)
{
	int retval;
	void *ch;
	struct chall_ctx cctx;
	const size_t keylen = fsc->algo.keylen_bytes;
	uint8_t key[keylen];
	uint8_t *iv = NULL;
	size_t ivlen = 0;
	uint8_t *ciphertext = NULL;
	size_t ciphertext_len = 0;

	memset(key, 0, keylen);
	memset(&cctx, 0, sizeof(struct chall_ctx));

	/* Retrieve the IV, if any */
	if (r->get_init_vector(r, &iv, &ivlen) != S_OK)
		return CRYPTO_UNKNOWN_ERROR;

	/* Retrieve the ciphertext */
	if (r->get_ciphertext(r, &ciphertext, &ciphertext_len) != S_OK) {
		mm_free(iv);
		return CRYPTO_UNKNOWN_ERROR;
	}

	/* Generate the challenge context */
	cctx.key_length = keylen;
	cctx.key = mm_malloc0(keylen);

	/* Walk over the list of challenges */
	for (size_t i = 0; i < fsc->num_challenges; i++) {
		if (fsc->challenges[i]) {
			ch = r->challenge_start(r, fsc->challenges[i]);
			if (!ch)
				goto end;

			/* Retrieve the challenge's params */
			retval = chall_get_params(r, ch, &cctx);
			if (retval != S_OK)
				goto end;

			retval = chall_run(fsc->handles[i], &cctx, ACTION_DECRYPT);
			if (retval != CRYPTO_OK) {
				log_e(fsc->logger, "[DECR] Could not get key from challenge %s\n",
						fsc->challenges[i]);

				retval = E_UNKNOWN;
				goto end;
			}

			r->challenge_end(r, ch);

			/* XOR and then reset the current key to zero */
			memxor(key, cctx.key, keylen);
			memset(cctx.key, 0, keylen);

			/* Free params and param names */
			chall_free_params(&cctx);

			log_i(fsc->logger, "[DECR] Got key from challenge %s\n", fsc->challenges[i]);
		}
	}

	retval = decrypt_internal(fsc, ciphertext, ciphertext_len, key, keylen, iv, ivlen, out, out_len);

end:
	mm_free(ciphertext);
	mm_free(iv);

	/* Destroy the secret key so that consumers don't have access to it */
	mm_free(cctx.key);
	cctx.key_length = 0;

	/* Free params and param names */
	chall_free_params(&cctx);

	return retval;
}

static int fsroot_run_challenges(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_len,
		const uint8_t *iv, size_t ivlen,
		void *f,
		cipher_action_t action)
{
	if (fsc->num_challenges == 0)
		return E_EMPTY;

	if (action == ACTION_ENCRYPT) {
		return fsroot_run_challenges_for_encryption(fsc, (file_formatter_t *) f,
				in, in_len,
				iv, ivlen,
				out, out_len);
	} else if (action == ACTION_DECRYPT) {
		return fsroot_run_challenges_for_decryption(fsc, (file_reader_t *) f,
				in, in_len,
				out, out_len);
	} else {
		return CRYPTO_INVALID_ALGORITHM;
	}
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

uint8_t *crypto_create_plaintext_buffer(crypto_t *fsc, size_t *plaintext_length)
{
	if (!plaintext_length || *plaintext_length == 0)
		return NULL;
	return crypto_create_plaintext_buffer_internal(fsc, plaintext_length);
}

int crypto_encrypt_with_challenges(crypto_t *fsc, file_formatter_t *fmt,
	const uint8_t *in, size_t in_len,
	uint8_t **out, size_t *out_len)
{
	char *algo;
	int retval = S_OK;
	uint8_t iv[AES_BLOCK_LENGTH];
	uint8_t *ciphertext_out;
	ssize_t ciphertext_len;

	if (!in || !in_len ||
		!out || !out_len ||
		!fmt)
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
	ciphertext_out = mm_malloc0(ciphertext_len);

	algo = crypto_get_algorithm_description(fsc, "<unknown>");
	log_i(fsc->logger, "Encrypting a file of length %zu bytes (algo: %s)\n", in_len, algo);
	mm_free(algo);

	/* Run the challenges and generate the ciphertext */
	pthread_rwlock_rdlock(&fsc->rwlock);
	retval = fsroot_run_challenges(fsc,
			in, in_len,
			ciphertext_out, ciphertext_len,
			iv, sizeof(iv),
			fmt,
			ACTION_ENCRYPT);
	pthread_rwlock_unlock(&fsc->rwlock);

	if (retval != S_OK) {
		mm_free(ciphertext_out);
		log_e(fsc->logger, "Encryption failed\n");
	} else {
		*out = ciphertext_out;
		*out_len = ciphertext_len;
	}

	return retval;
}

int crypto_encrypt_with_challenges2(crypto_t *fsc, file_formatter_t *fmt,
		const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_len)
{
	int retval;
	char *algo;
	ssize_t expected_len;
	uint8_t iv[AES_BLOCK_LENGTH];

	if (!fsc || !in || !out || !fmt)
		return E_BADARGS;

	if (fsc->algo.algo == ALGO_UNKNOWN ||
		fsc->algo.keylen == KEYLEN_UNKNOWN ||
		fsc->algo.mode == MODE_UNKNOWN)
		return E_NOTINITIALIZED;

	expected_len = get_expected_ciphertext_length(fsc, in_len);
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

	pthread_rwlock_rdlock(&fsc->rwlock);
	retval = fsroot_run_challenges(fsc,
			in, in_len,
			out, out_len,
			iv, sizeof(iv),
			fmt,
			ACTION_ENCRYPT);
	pthread_rwlock_unlock(&fsc->rwlock);

	if (retval != S_OK) {
		memset(out, 0, out_len);
		log_e(fsc->logger, "Encryption failed (inline)\n");
	}

	return retval;
}

int crypto_decrypt_with_challenges(crypto_t *fsc, file_reader_t *r,
		const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_len)
{
	int retval;
	char *algo;

	if (!fsc || !in || !out || !out_len || !r)
		return E_BADARGS;

	/* Check the algorithm has been properly initialized */
	if (fsc->algo.algo == ALGO_UNKNOWN ||
		fsc->algo.keylen == KEYLEN_UNKNOWN ||
		fsc->algo.mode == MODE_UNKNOWN)
		return E_NOTINITIALIZED;

	algo = crypto_get_algorithm_description(fsc, "<unknown>");
	log_i(fsc->logger, "Decrypting a file of length %zu bytes (algo: %s)\n", in_len, algo);
	mm_free(algo);

	pthread_rwlock_rdlock(&fsc->rwlock);
	retval = fsroot_run_challenges(fsc, in, in_len,
			out, out_len,
			NULL, 0,
			r,
			ACTION_DECRYPT);
	pthread_rwlock_unlock(&fsc->rwlock);

	if (retval != S_OK) {
		memset(out, 0, out_len);
		log_e(fsc->logger, "Decryption failed\n");
	}

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
