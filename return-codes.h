/*
 * return-codes.h
 *
 *  Created on: 28 Jul 2017
 *      Author: Ander Juaristi
 */
#ifndef __RETURN_CODES_H__
#define __RETURN_CODES_H__

#define S_EXISTS	 	 2
#define S_NOMORE		 1
#define S_OK		 	 0
#define E_BADARGS		-1
#define E_EXISTS		-2
#define E_NOTEXISTS		-3
#define E_NOMEM			-4
#define E_SYSCALL		-5
#define E_EOF			-6
#define E_NOTOPEN		-7
#define E_NOTINITIALIZED	-8
#define E_BUSY			-9
#define E_UNKNOWN		-10
#define E_NOT_DIRECTORY  	-11
#define E_NODB			-12
#define E_AGAIN			-13
#define E_NOTEMPTY		-14
#define E_NOTFOUND		-15
#define E_NOTSTARTED		-16
#define E_EMPTY			-17
#define E_TOOLARGE		-18

static const char *error2str(int err)
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
	}
}

#endif
