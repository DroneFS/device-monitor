/*
 * fsroot-crypto.c
 *
 *  Created on: 12 Sep 2017
 *      Author: Ander Juaristi
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <gcrypt.h>
#include "fsroot.h"
#include "fsroot-crypto.h"
#include "mm.h"

#define AES_KEY_LENGTH 16
#define AES_BLOCK_LENGTH 16

typedef int (* fsroot_cipher_func_t)(const uint8_t *, size_t,	/* Input */
		uint8_t **, size_t *,				/* Output */
		uint8_t *, size_t,				/* Key */
		const uint8_t *, size_t);			/* IV */

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

static int __encrypt(const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len,
		uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen)
{
	size_t padding_len;
	gcry_cipher_hd_t ctx;

	/* Initialize gcrypt */
	if (gcry_cipher_open(&ctx, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0) != 0)
		goto syscall_error;

	/* Allocate output buffer - inlen + padding length */
	padding_len = AES_BLOCK_LENGTH - (in_len % AES_BLOCK_LENGTH);
	*out_len = in_len + padding_len;
	*out = mm_malloc0(*out_len);

	/*
	 * Fill the padding - We use PKCS#7 padding
	 *
	 * We also take the chance to copy the input in the output buffer, and we encrypt
	 * in place. Since we're using CBC it's easier to do it this way because libgcrypt
	 * requires the padding to be present in the input before calling the encryption function.
	 */
	memcpy(*out, in, in_len);
	memset((*out) + in_len, (unsigned char) padding_len, padding_len);

	/* Key is always 128 bits for now */
	if (gcry_cipher_setkey(ctx, key, keylen) != 0)
		goto syscall_error;
	if (gcry_cipher_setiv(ctx, iv, ivlen) != 0)
		goto syscall_error;

	/* Encrypt */
	if (gcry_cipher_encrypt(ctx, *out, *out_len, NULL, 0) != 0)
		goto syscall_error;

	gcry_cipher_close(ctx);
	return FSROOT_OK;

syscall_error:
	gcry_cipher_close(ctx);
	mm_free(*out);
	return FSROOT_E_SYSCALL;
}

static int __decrypt(const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len,
		uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen)
{
	uint8_t *ptr, pad_len = 0, ctr = 0;
	gcry_cipher_hd_t ctx;

	/* Initialize gcrypt */
	if (gcry_cipher_open(&ctx, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0) != 0)
		goto syscall_error;

	if (gcry_cipher_setkey(ctx, key, keylen) != 0)
		goto syscall_error;
	if (gcry_cipher_setiv(ctx, iv, ivlen) != 0)
		goto syscall_error;

	/*
	 * Allocate output buffer to be of the same length
	 * as the input buffer - we'll remove the padding and resize
	 * after decryption
	 */
	*out_len = in_len;
	*out = mm_malloc0(in_len);

	/* Decrypt */
	if (gcry_cipher_decrypt(ctx, *out, *out_len, in, in_len) != 0)
		goto syscall_error;

	/* Remove padding and update output length */
	ptr = (*out) + (*out_len - 1);
	pad_len = *ptr;

	while (ctr < pad_len) {
		if ((*ptr) != pad_len)
			goto syscall_error;
		ptr--;
		ctr++;
	}

	*out_len -= pad_len;

	gcry_cipher_close(ctx);
	return FSROOT_OK;

syscall_error:
	gcry_cipher_close(ctx);
	mm_free(*out);
	return FSROOT_E_SYSCALL;
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
	size_t i;

	/* Unload the challenge at the designated index */
	mm_free(fsc->challenges[index]);
	dlclose(fsc->handles[index]);

	/* Bring the others front */
	for (i = index; i < fsc->num_challenges; i++) {
		fsc->challenges[i] = fsc->challenges[i + 1];
		fsc->handles[i] = fsc->handles[i + 1];
		fsc->challenges[i + 1] = NULL;
		fsc->handles[i + 1] = NULL;
	}
	fsc->challenges[i] = NULL;
	fsc->handles[i] = NULL;
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

	for (size_t i = 0; i < fsc->num_slots && fsc->challenges[i]; i++) {
		if (strcmp(fsc->challenges[i], libch) == 0) {
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

	retval = fsroot_run_challenges(fsc, in, in_len, &ciphertext_out, &ciphertext_len, iv, sizeof(iv), __encrypt);
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
	return fsroot_run_challenges(fsc, in, in_len, out, out_len, iv, ivlen, __decrypt);
}
