/*
 * fsroot-internal.h
 *
 *  Created on: 1 Aug 2017
 *      Author: Ander Juaristi
 */
#ifndef __FSROOT_INTERNAL_H__
#define __FSROOT_INTERNAL_H__
#include <pthread.h>

struct fsroot_file {
	char *path;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	struct {
		int sync      : 1;
		int tmpfile   : 1;
		int is_synced : 1;
		int delete    : 1;
	} flags;
	pthread_rwlock_t rwlock;
	char *buf;
	size_t buf_len;
};

#endif
