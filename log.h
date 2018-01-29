/*
 * log.h - Message logger
 *
 *  Created on: 14 Nov 2017
 *      Author: Ander Juaristi
 */
#ifndef __LOG_H__
#define __LOG_H__
#include <stdio.h>

struct logger
{
	FILE *i;
	FILE *e;
	FILE *d;
};

enum log_priorities {
	LOG_INFO,
	LOG_ERROR,
	LOG_DEBUG
};

void log_init(struct logger **);
void log_deinit(struct logger **);

void log_set_stream(struct logger *, enum log_priorities prio, FILE *);

#define PRINTF_FORMAT(x, y) __attribute__ ((format (printf, x, y)))

void log_i(struct logger *, const char *fmt, ...)
	PRINTF_FORMAT(2, 3);
void log_e(struct logger *, const char *fmt, ...)
	PRINTF_FORMAT(2, 3);
void log_d(struct logger *, const char *fmt, ...)
	PRINTF_FORMAT(2, 3);

#endif

