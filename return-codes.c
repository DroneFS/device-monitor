/*
 * return-codes.c
 *
 *  Created on: Jun 21, 2018
 *      Author: Ander Juaristi
 */
#include "return-codes.h"

const char *error2str(int err)
{
	switch (err) {
	case S_EXISTS:
		return "S_EXISTS";
	case S_NOMORE:
		return "S_NOMORE";
	case S_OK:
		return "S_OK";
	case E_BADARGS:
		return "E_BADARGS";
	case E_EXISTS:
		return "E_EXISTS";
	case E_NOTEXISTS:
		return "E_NOTEXISTS";
	case E_NOMEM:
		return "E_NOMEM";
	case E_SYSCALL:
		return "E_SYSCALL";
	case E_EOF:
		return "E_EOF";
	case E_NOTOPEN:
		return "E_NOTOPEN";
	case E_NOTINITIALIZED:
		return "E_NOTINITIALIZED";
	case E_BUSY:
		return "E_BUSY";
	case E_UNKNOWN:
		return "E_UNKNOWN";
	case E_NOT_DIRECTORY:
		return "E_NOT_DIRECTORY";
	case E_NODB:
		return "E_NODB";
	case E_AGAIN:
		return "E_AGAIN";
	case E_NOTEMPTY:
		return "E_NOTEMPTY";
	case E_NOTFOUND:
		return "E_NOTFOUND";
	case E_NOTSTARTED:
		return "E_NOTSTARTED";
	case E_EMPTY:
		return "E_EMPTY";
	case E_TOOLARGE:
		return "E_TOOLARGE";
	default:
		return "<unknown>";
	}
}
