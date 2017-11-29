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
	FILE *d;
};

enum log_priorities {
	LOG_INFO,
	LOG_DEBUG
};

void log_init(struct logger **);
void log_deinit(struct logger **);

void log_set_stream(struct logger *, enum log_priorities prio, FILE *);

void log_i(struct logger *, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
void log_d(struct logger *, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

#endif

