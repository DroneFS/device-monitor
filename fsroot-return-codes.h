/*
 * fsroot-return-codes.h
 *
 *  Created on: 28 Jul 2017
 *      Author: Ander Juaristi
 */
#define FSROOT_OK_EXISTS	 2
#define FSROOT_NOMORE		 1
#define FSROOT_OK		 0
#define FSROOT_E_BADARGS	-1
#define FSROOT_E_EXISTS		-2
#define FSROOT_E_NOTEXISTS	-3
#define FSROOT_E_NOMEM		-4
#define FSROOT_E_SYSCALL	-5
#define FSROOT_EOF		-6
#define FSROOT_E_NOTOPEN	-7
#define FSROOT_E_NOTINITIALIZED -8
#define FSROOT_E_BUSY		-9
#define FSROOT_E_UNKNOWN	-10
#define FSROOT_E_NOT_DIRECTORY  -11
#define FSROOT_E_NODB		-12
#define FSROOT_E_AGAIN		-13
#define FSROOT_E_NOTEMPTY	-14
#define FSROOT_E_NOTFOUND	-15
#define FSROOT_E_NOTSTARTED	-16
