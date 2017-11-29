/*
 * crypto-gcrypt.c
 *
 *  Created on: Nov 29, 2017
 *      Author: Ander Juaristi
 */
#include <gcrypt.h>
#include "mm.h"
#include "crypto-internal.h"
#include "fsroot-return-codes.h"

int encrypt_internal(const uint8_t *in, size_t in_len,
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
	padding_len = PADDING_LENGTH(in_len);
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

int decrypt_internal(const uint8_t *in, size_t in_len,
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

	/* FIXME padding should be removed in constant time */
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
