/*
 * crypto-gcrypt.c
 *
 *  Created on: Nov 29, 2017
 *      Author: Ander Juaristi
 */
#include <gcrypt.h>
#include "mm.h"
#include "crypto-internal.h"
#include "return-codes.h"

int encrypt_internal(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len,
		uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen)
{
	int retval = CRYPTO_UNKNOWN_ERROR;
	size_t padding_len;
	gcry_cipher_hd_t ctx = NULL;

	/* Key is always 128 bits for now */
	if (keylen != AES_KEY_LENGTH) {
		retval = CRYPTO_INVALID_KEY_LEN;
		goto end;
	}

	/* Check proper length of IV */
	if (ivlen != AES_BLOCK_LENGTH) {
		retval = CRYPTO_INVALID_IV_LEN;
		goto end;
	}

	/* Allocate output buffer - inlen + padding length */
	padding_len = PADDING_LENGTH(in_len);
	*out_len = in_len + padding_len;
	*out = mm_malloc0(*out_len);

	/* Initialize gcrypt */
	switch (fsc->algo.mode) {
	case MODE_CBC:
		if (gcry_cipher_open(&ctx, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0) != 0)
			goto end;

		/*
		 * Fill the padding - We use PKCS#7 padding
		 *
		 * We also take the chance to copy the input in the output buffer, and we encrypt
		 * in place. Since we're using CBC it's easier to do it this way because libgcrypt
		 * requires the padding to be present in the input before calling the encryption function.
		 */
		memcpy(*out, in, in_len);
		memset((*out) + in_len, (unsigned char) padding_len, padding_len);

		if (gcry_cipher_setiv(ctx, iv, ivlen) != 0) {
			retval = CRYPTO_UNKNOWN_ERROR;
			goto end;
		}

		break;
	case MODE_CTR:
		*out_len -= padding_len;

		if (gcry_cipher_open(&ctx, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0) != 0)
			goto end;

		if (gcry_cipher_setctr(ctx, iv, ivlen) != 0) {
			retval = CRYPTO_UNKNOWN_ERROR;
			goto end;
		}

		break;
	default:
		return CRYPTO_INVALID_MODE;
	}

	if (gcry_cipher_setkey(ctx, key, keylen) != 0) {
		retval = CRYPTO_UNKNOWN_ERROR;
		goto end;
	}

	/* Encrypt */
	if (gcry_cipher_encrypt(ctx, *out, *out_len, NULL, 0) != 0)
		goto end;

	gcry_cipher_close(ctx);
	return S_OK;

end:
	gcry_cipher_close(ctx);
	mm_free(*out);
	return retval;
}

int decrypt_internal(crypto_t *fsc,
		const uint8_t *in, size_t in_len,
		uint8_t **out, size_t *out_len,
		uint8_t *key, size_t keylen,
		const uint8_t *iv, size_t ivlen)
{
	int retval = CRYPTO_UNKNOWN_ERROR;
	uint8_t *ptr, pad_len = 0, ctr = 0;
	gcry_cipher_hd_t ctx;

	/* Key is always 128 bits for now */
	if (keylen != AES_KEY_LENGTH) {
		retval = CRYPTO_INVALID_KEY_LEN;
		goto end;
	}

	/* Check proper length of IV */
	if (ivlen != AES_BLOCK_LENGTH) {
		retval = CRYPTO_INVALID_IV_LEN;
		goto end;
	}

	/*
	 * Allocate output buffer to be of the same length
	 * as the input buffer - we'll remove the padding and resize
	 * after decryption
	 */
	*out_len = in_len;
	*out = mm_malloc0(in_len);

	/* Initialize gcrypt */
	switch (fsc->algo.mode) {
	case MODE_CBC:
		if (gcry_cipher_open(&ctx, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0) != 0)
			goto end;

		if (gcry_cipher_setiv(ctx, iv, ivlen) != 0) {
			retval = CRYPTO_UNKNOWN_ERROR;
			goto end;
		}

		break;
	case MODE_CTR:
		if (gcry_cipher_open(&ctx, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CTR, 0) != 0)
			goto end;

		if (gcry_cipher_setctr(ctx, iv, ivlen) != 0) {
			retval = CRYPTO_UNKNOWN_ERROR;
			goto end;
		}

		break;
	default:
		return CRYPTO_INVALID_MODE;
	}

	if (gcry_cipher_setkey(ctx, key, keylen) != 0) {
		retval = CRYPTO_UNKNOWN_ERROR;
		goto end;
	}

	/* Decrypt */
	if (gcry_cipher_decrypt(ctx, *out, *out_len, in, in_len) != 0)
		goto end;

	if (fsc->algo.mode == MODE_CBC) {
		/* Remove padding and update output length */
		ptr = (*out) + (*out_len - 1);
		pad_len = *ptr;

		/* FIXME padding should be removed in constant time */
		while (ctr < pad_len) {
			if ((*ptr) != pad_len)
				goto end;
			ptr--;
			ctr++;
		}

		*out_len -= pad_len;
	}

	gcry_cipher_close(ctx);
	return S_OK;

end:
	gcry_cipher_close(ctx);
	mm_free(*out);
	return retval;
}
