/*
 * fsroot-db.h
 *
 *  Created on: 28 Jul 2017
 *      Author: Ander Juaristi
 */
#ifndef __FSROOT_DB_H__
#define __FSROOT_DB_H__
#include "fsroot-internal.h"
#include "return-codes.h"

struct fsroot_db_st;
typedef struct fsroot_db_st fsroot_db_t;
typedef struct fsroot_db_iter_st fsroot_db_iter_t;

int fsroot_db_create(const char *);
int fsroot_db_open(const char *, fsroot_db_t **);
int fsroot_db_add_file_entry(fsroot_db_t *, const char *, struct fsroot_file *);
int fsroot_db_close(fsroot_db_t **);

int fsroot_db_iter_init(fsroot_db_iter_t **, fsroot_db_t *);
int fsroot_db_iter_next(fsroot_db_iter_t *, char **, struct fsroot_file *);
void fsroot_db_iter_deinit(fsroot_db_iter_t **);

#endif

