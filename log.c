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

struct logger
{
	union {
		struct {
			FILE *i;
			FILE *e;
			FILE *d;
		};
		logger_function_t func;
	};

	enum {
		UNSET = 0,
		STREAM,
		FUNCTION
	} type;
};

void log_init(logger_t **l)
{
	if (l)
		*l = mm_new0(struct logger);
}

void log_deinit(logger_t **l)
{
	if (l)
		mm_free(*l);
}

void log_set_stream(logger_t *l, enum log_priorities prio, FILE *fp)
{
	if (l && fp) {
		l->type = STREAM;

		switch (prio) {
		case LOG_INFO:
			l->i = fp;
			break;
		case LOG_ERROR:
			l->e = fp;
			break;
		case LOG_DEBUG:
			l->d = fp;
			break;
		}
	}
}

void log_set_function(logger_t *l, logger_function_t func)
{
	if (l && func) {
		l->type = FUNCTION;
		l->func = func;
	}
}

static void vlog_stream(struct logger *l,
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
	case LOG_ERROR:
		stream = l->e;
		prefix = "[ERROR] ";
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

static void vlog_func(struct logger *l,
		enum log_priorities prio,
		const char *fmt, va_list args)
{
	if (l->func)
		l->func(l, prio, fmt, args);
}

static void vlog(struct logger *l,
	enum log_priorities prio,
	const char *fmt, va_list args)
{
	if (l->type == STREAM)
		vlog_stream(l, prio, fmt, args);
	else
		vlog_func(l, prio, fmt, args);
}

void log_i(logger_t *l, const char *fmt, ...)
{
	va_list args;

	if (l && fmt) {
		va_start(args, fmt);
		vlog(l, LOG_INFO, fmt, args);
		va_end(args);
	}
}

void log_e(logger_t *l, const char *fmt, ...)
{
	va_list args;

	if (l && fmt) {
		va_start(args, fmt);
		vlog(l, LOG_ERROR, fmt, args);
		va_end(args);
	}
}

void log_d(logger_t *l, const char *fmt, ...)
{
	va_list args;

	if (l && fmt) {
		va_start(args, fmt);
		vlog(l, LOG_DEBUG, fmt, args);
		va_end(args);
	}
}
