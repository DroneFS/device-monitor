/*
 * crypto-openssl.c
 *
 *  Created on: Nov 29, 2017
 *      Author: Ander Juaristi
 */
#include <string.h>
#include <openssl/aes.h>
#include "crypto-internal.h"
#include "mm.h"
#include "return-codes.h"

int encrypt_internal(const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len,
		uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen)
{
	AES_KEY aes_key;
	unsigned char *tmp_iv;

	if (keylen != AES_KEY_LENGTH)
		return E_SYSCALL;

	if (AES_set_encrypt_key(key, 128, &aes_key) != 0)
		return E_SYSCALL;

	tmp_iv = mm_malloc0(ivlen);
	memcpy(tmp_iv, iv, ivlen);

	*out_len = in_len + PADDING_LENGTH(in_len);
	*out = mm_malloc0(*out_len);

	/*
	 * No need to call EVP_CIPHER_CTX_set_padding().
	 * We're using PKCS#7 padding and that's OpenSSL's default.
	 */
	AES_cbc_encrypt(in, *out, in_len, &aes_key, tmp_iv, AES_ENCRYPT);

	mm_free(tmp_iv);
	return S_OK;
}

int decrypt_internal(const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len,
		uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen)
{
	AES_KEY aes_key;
	unsigned char *tmp_iv;

	if (keylen != AES_KEY_LENGTH)
		return E_SYSCALL;

	if (AES_set_decrypt_key(key, 128, &aes_key) != 0)
		return E_SYSCALL;

	tmp_iv = mm_malloc0(ivlen);
	memcpy(tmp_iv, iv, ivlen);

	*out_len = in_len;
	*out = mm_malloc0(*out_len);

	AES_cbc_encrypt(in, *out, in_len, &aes_key, tmp_iv, AES_DECRYPT);

	mm_free(tmp_iv);
	return S_OK;
}
