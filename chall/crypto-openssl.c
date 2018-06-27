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

static int AES_CBC_encrypt(const uint8_t *in, size_t in_len,
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

	if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		goto end;
	if (!EVP_EncryptUpdate(ctx, out, &outlen, in, in_len))
		goto end;
	if (!EVP_EncryptFinal_ex(ctx, out + outlen, &outlen))
		goto end;

	retval = CRYPTO_OK;

end:
	EVP_CIPHER_CTX_free(ctx);
	return retval;
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
	if (!EVP_EncryptFinal_ex(ctx, out + outlen, &outlen))
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
	unsigned char *tmp_iv;

	if (keylen != AES_KEY_LENGTH)
		return CRYPTO_INVALID_KEY_LEN;

	/* Check for proper length of IV */
	if (ivlen != AES_BLOCK_SIZE)
		return CRYPTO_INVALID_IV_LEN;

	/* Copy first 8 bytes of IV */
	tmp_iv = mm_malloc0(ivlen);
	memcpy(tmp_iv, iv, ivlen);

	switch (fsc->algo.mode) {
	case MODE_CBC:
		retval = AES_CBC_encrypt(in, in_len, out, out_len, key, tmp_iv);
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

static int AES_CBC_decrypt(const uint8_t *in, size_t in_len,
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

	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		goto end;
	if (!EVP_DecryptUpdate(ctx, out, &outlen, in, in_len))
		goto end;
	if (!EVP_DecryptFinal_ex(ctx, out + outlen, &outlen))
		goto end;

	retval = CRYPTO_OK;

end:
	EVP_CIPHER_CTX_free(ctx);
	return retval;
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
		retval = AES_CBC_decrypt(in, in_len, out, out_len, key, tmp_iv);
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

uint8_t *crypto_create_plaintext_buffer_internal(crypto_t *fsc, size_t *plaintext_len)
{
	size_t ct_len = *plaintext_len;

	if (fsc->algo.mode == MODE_CBC)
		ct_len += EVP_MAX_BLOCK_LENGTH;

	if (ct_len == 0)
		return NULL;

	*plaintext_len = ct_len;
	return mm_malloc0(ct_len);
}
