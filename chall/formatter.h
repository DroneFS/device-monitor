/*
 * formatter.h
 *
 *  Created on: Apr 23, 2018
 *      Author: Ander Juaristi
 */

#ifndef FORMATTER_H_
#define FORMATTER_H_

#include <stdint.h>
#include "return-codes.h"

struct file_formatter_st;
typedef struct file_formatter_st file_formatter_t;

struct file_reader_st;
typedef struct file_reader_st file_reader_t;

struct file_formatter_st
{
	int (* start_document) (file_formatter_t *);
	int (* end_document) (file_formatter_t *, int);

	void (* set_file_name) (file_formatter_t *, const char *);
	void (* set_version) (file_formatter_t *, int);
	int (* set_init_vector) (file_formatter_t *, const unsigned char *, size_t);
	void (* set_plaintext_length) (file_formatter_t *, size_t);

	void * (* challenge_start) (file_formatter_t *, const char *);
	int (* set_param) (void *, const char *, const char *);
	void (* challenge_end) (file_formatter_t *, void *);

	int (* set_ciphertext) (file_formatter_t *, const unsigned char *, size_t);

	void *priv;
};

struct file_reader_st
{
	int (* start_document) (file_reader_t *, const uint8_t *, size_t);
	int (* end_document) (file_reader_t *);

	void * (* challenge_start) (file_reader_t *, const char *);
	void (*challenge_end) (file_reader_t *, void *);

	int (* get_num_params) (void *);
	int (* get_param) (void *, unsigned int,
			unsigned char **, unsigned char **);

	int (*get_ciphertext) (file_reader_t *, uint8_t **, size_t *);
	int (* get_init_vector) (file_reader_t *, uint8_t **, size_t *);

	size_t (* get_plaintext_length) (file_reader_t *);

	void *priv;
	const char *file_path;
};

#endif /* FORMATTER_H_ */
