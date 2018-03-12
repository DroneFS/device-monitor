/*
 * fsroot.h
 *
 *  Created on: 21 Oct 2016
 *      Author: Ander Juaristi
 */
#ifndef FSROOT_H_
#define FSROOT_H_
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "log.h"
#include "return-codes.h"

struct _fsroot_st;
typedef struct _fsroot_st fsroot_t;

int fsroot_init(fsroot_t **, struct logger *);
void fsroot_deinit(fsroot_t **);
int fsroot_start(fsroot_t *, uid_t, gid_t, mode_t);
int fsroot_persist(fsroot_t *, const char *filename);

int fsroot_set_root_directory(fsroot_t *, const char *);
int fsroot_set_database_file(fsroot_t *, const char *);
int fsroot_set_config_file(fsroot_t *fs, const char *filename);

int fsroot_create(fsroot_t *, const char *path, uid_t uid, gid_t gid, mode_t mode, int flags, int *error_out);
int fsroot_open(fsroot_t *, const char *path, int flags);
int fsroot_read(fsroot_t *, int fd, char *buf, size_t size, off_t offset, int *error_out);
int fsroot_write(fsroot_t *, int fd, const char *buf, size_t size, off_t offset, int *error_out);
int fsroot_sync(fsroot_t *, const char *path);
int fsroot_release(fsroot_t *, const char *path);

int fsroot_getattr(fsroot_t *, const char *path, struct stat *out_st);

int fsroot_symlink(fsroot_t *, const char *linkpath, const char *target, uid_t uid, gid_t gid, mode_t mode);
int fsroot_readlink(fsroot_t *, const char *linkpath, char *dst, size_t *dstlen);

int fsroot_mkdir(fsroot_t *, const char *path, uid_t uid, gid_t gid, mode_t mode);
int fsroot_rmdir(fsroot_t *, const char *path);

int fsroot_rename(fsroot_t *, const char *path, const char *newpath);
int fsroot_chmod(fsroot_t *, const char *path, mode_t mode);
int fsroot_chown(fsroot_t *, const char *path, uid_t uid, gid_t gid);

int fsroot_opendir(fsroot_t *, const char *path, void **outdir, int *error);
int fsroot_readdir(void *dir, char *out, size_t outlen, int *err);
void fsroot_closedir(void **dir);

#endif /* FSROOT_H_ */
