/*
 * log.c - Message logger
 *
 *  Created on: 14 Nov 2017
 *      Author: Ander Juaristi
 */
#include <stdarg.h>
#include "log.h"
#include "mm.h"
#include "return-codes.h"

void log_init(struct logger **l)
{
	if (l)
		*l = mm_new0(struct logger);
}

void log_deinit(struct logger **l)
{
	if (l)
		mm_free(*l);
}

void log_set_stream(struct logger *l, enum log_priorities prio, FILE *fp)
{
	if (l && fp) {
		switch (prio) {
		case LOG_INFO:
			l->i = fp;
			break;
		case LOG_DEBUG:
			l->d = fp;
			break;
		}
	}
}

static void vlog(struct logger *l,
	enum log_priorities prio,
	const char *fmt, va_list args)
{
	char *prefix;
	FILE *stream = NULL;

	switch (prio) {
	case LOG_INFO:
		stream = l->i;
		prefix = "[INFO] ";
		break;
	case LOG_DEBUG:
		stream = l->d;
		prefix = "[DEBUG] ";
		break;
	}

	if (stream) {
		fprintf(stream, "%s", prefix);
		vfprintf(stream, fmt, args);
	}
}

void log_i(struct logger *l, const char *fmt, ...)
{
	va_list args;

	if (l && fmt) {
		va_start(args, fmt);
		vlog(l, LOG_INFO, fmt, args);
		va_end(args);
	}
}

void log_d(struct logger *l, const char *fmt, ...)
{
	va_list args;

	if (l && fmt) {
		va_start(args, fmt);
		vlog(l, LOG_DEBUG, fmt, args);
		va_end(args);
	}
}
