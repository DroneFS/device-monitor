/*
 * fsroot-crypto.c
 *
 *  Created on: 12 Sep 2017
 *      Author: Ander Juaristi
 */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <dlfcn.h>
#include "fsroot-return-codes.h"
#include "fsroot-crypto.h"
#include "crypto-internal.h"
#include "mm.h"

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

static int load_challenge(fsroot_crypto_t *fsc, const char *libch, unsigned int index)
{
	void *handle = dlopen(libch, RTLD_NOW);

	if (!handle)
		return FSROOT_E_SYSCALL;

	/* Library was loaded successfully - copy handle and name in the structure */
	fsc->challenges[index] = strdup(libch);
	fsc->handles[index] = handle;
	return FSROOT_OK;
}

static void unload_challenge(fsroot_crypto_t *fsc, unsigned int index)
{
	/* Unload the challenge at the designated index */
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

static int fsroot_run_challenges(fsroot_crypto_t *fsc,
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
			if (!tmp_key)
				return FSROOT_E_UNKNOWN;

			/* key is a 128 bit (16 bytes) value */
			memxor(key, tmp_key, keylen);
			mm_free(tmp_key);
		}
	}

	return f(in, in_len, out, out_len, key, keylen, iv, ivlen);
}

#define INITIAL_SLOTS 5

void fsroot_crypto_init(fsroot_crypto_t *fsc)
{
	fsc->num_challenges = 0;
	fsc->num_slots = INITIAL_SLOTS;
	fsc->challenges = mm_new(INITIAL_SLOTS, char *);
	fsc->handles = mm_new(INITIAL_SLOTS, void *);
}

void fsroot_crypto_deinit(fsroot_crypto_t *fsc)
{
	fsroot_crypto_unload_all_challenges(fsc);

	fsc->num_challenges = 0;
	fsc->num_slots = 0;
	mm_free(fsc->challenges);
	mm_free(fsc->handles);
}

static void resize_slots(fsroot_crypto_t *fsc)
{
	size_t num_slots = fsc->num_slots << 1;
	mm_realloc(fsc->challenges, num_slots);
	mm_realloc(fsc->handles, num_slots);
	fsc->num_slots = num_slots;
}

int fsroot_crypto_load_challenge(fsroot_crypto_t *fsc, const char *libch)
{
	/* 'FSROOT_E_NOMEM' means we reached the maximum number challenges allowed (currently 5) */
	int retval = FSROOT_E_NOMEM;

	if (!fsc || !libch || !*libch)
		return FSROOT_E_BADARGS;
	if (fsc->num_challenges == SIZE_MAX)
		return FSROOT_E_NOMEM;

	if (fsc->num_slots == fsc->num_challenges) {
		if ((fsc->num_slots + 1) >= SIZE_MAX)
			return FSROOT_E_NOMEM;
		resize_slots(fsc);
	}

	for (size_t i = 0; i < fsc->num_slots; i++) {
		if (fsc->challenges[i] && strcmp(fsc->challenges[i], libch) == 0) {
			/* This challenge is already loaded */
			retval = FSROOT_OK;
			break;
		} else if (fsc->challenges[i] == NULL) {
			/* We load this challenge at the designated index */
			retval = load_challenge(fsc, libch, i);
			if (retval == FSROOT_OK)
				fsc->num_challenges++;
			break;
		}
	}

	return retval;
}

int fsroot_crypto_unload_challenge(fsroot_crypto_t *fsc, const char *libch)
{
	int retval = FSROOT_E_NOTFOUND;

	for (size_t i = 0; i < fsc->num_slots; i++) {
		if (fsc->challenges[i] && strcmp(fsc->challenges[i], libch) == 0) {
			unload_challenge(fsc, i);
			fsc->num_challenges--;
			retval = FSROOT_OK;
			break;
		}
	}

	return retval;
}

int fsroot_crypto_encrypt_with_challenges(fsroot_crypto_t *fsc,
	const uint8_t *in, size_t in_len,
	uint8_t **out, size_t *out_len)
{
	int retval = FSROOT_OK;
	uint8_t iv[AES_BLOCK_LENGTH];
	uint8_t *ciphertext_out;
	size_t ciphertext_len;

	if (!in || !in_len ||
		!out || !out_len)
		return FSROOT_E_BADARGS;

	/* Generate a random IV of the same length as the AES block size */
	if (get_random_bytes(iv, sizeof(iv)) < sizeof(iv))
		return FSROOT_E_SYSCALL;

	retval = fsroot_run_challenges(fsc, in, in_len,
			&ciphertext_out, &ciphertext_len,
			iv, sizeof(iv),
			encrypt_internal);
	if (retval != FSROOT_OK)
		goto end;

	/* Return a blob with the IV + the ciphertext */
	*out_len = sizeof(iv) + ciphertext_len;
	*out = mm_malloc0(*out_len);
	memcpy(*out, iv, sizeof(iv));
	memcpy((*out) + sizeof(iv), ciphertext_out, ciphertext_len);
	mm_free(ciphertext_out);

end:
	return retval;
}

int fsroot_crypto_decrypt_with_challenges(fsroot_crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len)
{
	/* IV comes first */
	const uint8_t *iv = in;
	size_t ivlen = AES_BLOCK_LENGTH;

	/* Ciphertext comes right after IV */
	in += ivlen;
	in_len -= ivlen;
	return fsroot_run_challenges(fsc, in, in_len,
			out, out_len,
			iv, ivlen,
			decrypt_internal);
}

/**
 * \param[in] fsc
 * \return The number of challenges loaded
 */
size_t fsroot_crypto_num_challenges_loaded(fsroot_crypto_t *fsc)
{
	return (fsc ? fsc->num_challenges : 0);
}

static int config_load_challenges(fsroot_crypto_t *fsc, config_value_t *it)
{
	int retval;
	char *chall_name;
	config_value_t *val = NULL;

	while (config_iterator_next(it, &val) == CONFIG_OK) {
		if (config_get_as_string(val, &chall_name) == CONFIG_OK) {
			/* Load the challenge */
			retval = fsroot_crypto_load_challenge(fsc, chall_name);
			mm_free(chall_name);
			if (retval != FSROOT_OK)
				break;
		}
	}

	config_destroy_value(&val);
	return retval;
}

static int config_load_challenge(fsroot_crypto_t *fsc, config_value_t *val)
{
	char *chall_name;
	int retval = FSROOT_E_UNKNOWN;

	if (config_get_as_string(val, &chall_name) == CONFIG_OK) {
		retval = fsroot_crypto_load_challenge(fsc, chall_name);
		mm_free(chall_name);
	}

	return retval;
}

/**
 * \param[in] fsc
 * \param[in] c
 * \return The number of challenges loaded, or negative value on error
 */
int fsroot_crypto_load_challenges_from_config(fsroot_crypto_t *fsc, config_t *c)
{
	int retval;
	config_value_t *val = NULL;

	if (!fsc || !c)
		return FSROOT_E_BADARGS;

	if (config_get_value(c, &val, "challenges") == CONFIG_OK) {
		if (config_is_iterator(val))
			retval = config_load_challenges(fsc, val);
		else if (config_is_string(val))
			retval = config_load_challenge(fsc, val);

		config_destroy_value(&val);
	}

	if (retval == FSROOT_OK) {
		return (fsc->num_challenges >= INT_MAX ?
				INT_MAX :
				fsc->num_challenges);
	} else {
		return retval;
	}
}

/**
 * \param[in] fsc
 */
void fsroot_crypto_unload_all_challenges(fsroot_crypto_t *fsc)
{
	if (fsc->num_challenges > 0) {
		for (size_t i = 0; i < fsc->num_challenges; i++)
			unload_challenge(fsc, i);
		fsc->num_challenges = 0;
	}
}
