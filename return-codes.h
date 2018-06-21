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

const char *error2str(int);

#endif
