/*
 * log.h - Message logger
 *
 *  Created on: 14 Nov 2017
 *      Author: Ander Juaristi
 */
#ifndef __LOG_H__
#define __LOG_H__
#include <stdio.h>

struct logger;
typedef struct logger logger_t;

enum log_priorities {
	LOG_INFO,
	LOG_ERROR,
	LOG_DEBUG
};

typedef void (* logger_function_t) (logger_t *, enum log_priorities, const char *, va_list args);

void log_init(logger_t **);
void log_deinit(logger_t **);

void log_set_function(logger_t *, logger_function_t);
void log_set_stream(logger_t *, enum log_priorities, FILE *);

#define PRINTF_FORMAT(x, y) __attribute__ ((format (printf, x, y)))

void log_i(logger_t *, const char *fmt, ...)
	PRINTF_FORMAT(2, 3);
void log_e(logger_t *, const char *fmt, ...)
	PRINTF_FORMAT(2, 3);
void log_d(logger_t *, const char *fmt, ...)
	PRINTF_FORMAT(2, 3);

#endif

