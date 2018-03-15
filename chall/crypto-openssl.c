/*
 * crypto-openssl.c
 *
 *  Created on: Nov 29, 2017
 *      Author: Ander Juaristi
 */
#include <string.h>
#include <openssl/aes.h>
#include <openssl/modes.h>
#include "crypto-internal.h"
#include "mm.h"
#include "return-codes.h"

struct ctr_state
{
	unsigned int num;
	unsigned char ivec[AES_BLOCK_SIZE];
	unsigned char ecount[AES_BLOCK_SIZE];
};

static void AES_CBC_encrypt(const uint8_t *in, size_t in_len,
		uint8_t *out,
		const AES_KEY *key,
		unsigned char *iv)
{
	/*
	 * No need to call EVP_CIPHER_CTX_set_padding().
	 * We're using PKCS#7 padding and that's OpenSSL's default.
	 */
	AES_cbc_encrypt(in, out, in_len, key, iv, AES_ENCRYPT);
}

static void init_ctr(struct ctr_state *state, const unsigned char *iv)
{
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);
	memcpy(state->ivec, iv, AES_BLOCK_SIZE);
}

static void AES_CTR_encrypt(const uint8_t *in, size_t in_len,
		uint8_t *out,
		const AES_KEY *key,
		unsigned char *iv)
{
	struct ctr_state state;

	init_ctr(&state, iv);

	CRYPTO_ctr128_encrypt(in, out, in_len, key,
			state.ivec, state.ecount, &state.num,
			(void (*) (const unsigned char *, unsigned char *, const void *)) AES_encrypt);
}

int encrypt_internal(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len,
		uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen)
{
	int retval = S_OK;
	AES_KEY aes_key;
	unsigned char *tmp_iv;

	if (keylen != AES_KEY_LENGTH)
		return CRYPTO_INVALID_KEY_LEN;

	if (AES_set_encrypt_key(key, 128, &aes_key) != 0)
		return CRYPTO_UNKNOWN_ERROR;

	/* Check for proper length of IV */
	if (ivlen != AES_BLOCK_SIZE)
		return CRYPTO_INVALID_IV_LEN;

	/* Copy first 8 bytes of IV */
	tmp_iv = mm_malloc0(ivlen);
	memcpy(tmp_iv, iv, ivlen);

	*out_len = in_len + PADDING_LENGTH(in_len);
	*out = mm_malloc0(*out_len);

	switch (fsc->algo.mode) {
	case MODE_CBC:
		AES_CBC_encrypt(in, in_len, *out, &aes_key, tmp_iv);
		break;
	case MODE_CTR:
		*out_len -= PADDING_LENGTH(in_len);
		AES_CTR_encrypt(in, in_len, *out, &aes_key, tmp_iv);
		break;
	default:
		retval = CRYPTO_INVALID_MODE;
		break;
	}

	mm_free(tmp_iv);

	if (retval != S_OK) {
		mm_free(*out);
		*out_len = 0;
	}

	return retval;
}

static void AES_CBC_decrypt(const uint8_t *in, size_t in_len,
		uint8_t *out,
		const AES_KEY *key,
		unsigned char *iv)
{
	AES_cbc_encrypt(in, out, in_len, key, iv, AES_DECRYPT);
}

static void AES_CTR_decrypt(const uint8_t *in, size_t in_len,
		uint8_t *out,
		const AES_KEY *key,
		unsigned char *iv)
{
	/* Decryption and encryption are symmetric in CTR mode */
	AES_CTR_encrypt(in, in_len, out, key, iv);
}

int decrypt_internal(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len,
		uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen)
{
	int retval = S_OK;
	AES_KEY aes_key;
	unsigned char *tmp_iv;

	if (keylen != AES_KEY_LENGTH)
		return CRYPTO_INVALID_KEY_LEN;

	/* Check for proper length of IV */
	if (ivlen != AES_BLOCK_SIZE)
		return CRYPTO_INVALID_IV_LEN;

	/* Copy the first 8 bits of IV */
	tmp_iv = mm_malloc0(ivlen);
	memcpy(tmp_iv, iv, ivlen);

	*out_len = in_len;
	*out = mm_malloc0(*out_len);

	switch (fsc->algo.mode) {
	case MODE_CBC:
		if (AES_set_decrypt_key(key, 128, &aes_key) != 0)
			retval = CRYPTO_UNKNOWN_ERROR;
		else
			AES_CBC_decrypt(in, in_len, *out, &aes_key, tmp_iv);
		break;
	case MODE_CTR:
		if (AES_set_encrypt_key(key, 128, &aes_key) != 0)
			retval = CRYPTO_UNKNOWN_ERROR;
		else
			AES_CTR_decrypt(in, in_len, *out, &aes_key, tmp_iv);
		break;
	default:
		retval = CRYPTO_INVALID_MODE;
		break;
	}

	mm_free(tmp_iv);

	if (retval != S_OK) {
		mm_free(*out);
		*out_len = 0;
	}

	return retval;
}
