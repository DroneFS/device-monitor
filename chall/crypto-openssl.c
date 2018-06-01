/*
 * crypto-openssl.c
 *
 *  Created on: Nov 29, 2017
 *      Author: Ander Juaristi
 */
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include "crypto-internal.h"
#include "mm.h"
#include "return-codes.h"

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

static int AES_CTR_encrypt(const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_len,
		const unsigned char *key,
		const unsigned char *iv)
{
	int retval = CRYPTO_UNKNOWN_ERROR,
		outlen = out_len;
	EVP_CIPHER_CTX *ctx;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return CRYPTO_UNKNOWN_ERROR;

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
		goto end;
	if (!EVP_EncryptUpdate(ctx, out, &outlen, in, in_len))
		goto end;
	if (!EVP_EncryptFinal(ctx, out + outlen, &outlen))
		goto end;

	retval = CRYPTO_OK;

end:
	EVP_CIPHER_CTX_free(ctx);
	return retval;
}

int encrypt_internal(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen,
		uint8_t *out, size_t out_len)
{
	int retval = S_OK;
	AES_KEY aes_key;
	unsigned char *tmp_iv;

	if (keylen != AES_KEY_LENGTH)
		return CRYPTO_INVALID_KEY_LEN;

	/* Copy first 8 bytes of IV */
	tmp_iv = mm_malloc0(ivlen);
	memcpy(tmp_iv, iv, ivlen);

	switch (fsc->algo.mode) {
	case MODE_CBC:
		if (AES_set_encrypt_key(key, 128, &aes_key) != 0)
			return CRYPTO_UNKNOWN_ERROR;

		/* Check for proper length of IV */
		if (ivlen != AES_BLOCK_SIZE)
			return CRYPTO_INVALID_IV_LEN;

		AES_CBC_encrypt(in, in_len, out, &aes_key, tmp_iv);
		break;
	case MODE_CTR:
		retval = AES_CTR_encrypt(in, in_len, out, out_len, key, tmp_iv);
		break;
	default:
		retval = CRYPTO_INVALID_MODE;
		break;
	}

	mm_free(tmp_iv);
	return retval;
}

static void AES_CBC_decrypt(const uint8_t *in, size_t in_len,
		uint8_t *out,
		const AES_KEY *key,
		unsigned char *iv)
{
	AES_cbc_encrypt(in, out, in_len, key, iv, AES_DECRYPT);
}

static int AES_CTR_decrypt(const uint8_t *in, size_t in_len,
		uint8_t *out, size_t out_len,
		const unsigned char *key,
		const unsigned char *iv)
{
	/* Decryption and encryption are symmetric in CTR mode */
	return AES_CTR_encrypt(in, in_len, out, out_len, key, iv);
}

int decrypt_internal(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen,
		uint8_t *out, size_t out_len)
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

	switch (fsc->algo.mode) {
	case MODE_CBC:
		if (AES_set_decrypt_key(key, 128, &aes_key) != 0)
			retval = CRYPTO_UNKNOWN_ERROR;
		else
			AES_CBC_decrypt(in, in_len, out, &aes_key, tmp_iv);
		break;
	case MODE_CTR:
		retval = AES_CTR_decrypt(in, in_len, out, out_len, key, tmp_iv);
		break;
	default:
		retval = CRYPTO_INVALID_MODE;
		break;
	}

	mm_free(tmp_iv);
	return retval;
}
