/*
 * fuse.c
 *
 *  Created on: 21 Oct 2016
 *      Author: Ander Juaristi
 *
 *  Unsupported operations:
 *  	- link
 *  	- statfs
 *  	- flush
 *  	- release ??? -> we have to open+close with every open()
 *  	- fsync
 *  	- setxattr
 *  	- getxattr
 *  	- listxattr
 *  	- removexattr
 *  	- releasedir ???
 *  	- fsyncdir
 *  	- destroy
 *  	- lock
 *  	- utimens
 *  	- bmap
 *  	- ioctl
 *  	- poll
 *  	- write_buf
 *  	- read_buf
 *  	- flock
 *  	- fallocate
 *  	- create
 */
#define FUSE_USE_VERSION 30
#include <stdio.h>	/* rename(2) */
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
#include <unistd.h>	/* rmdir(2), stat(2), unlink(2), chown(2),... */
#include <sys/stat.h>	/* mkdir(2), chmod(2) */
#include <dirent.h>
#include <stddef.h>	/* offsetof() macro */
#include <errno.h>
#include <fuse.h>
#include <fuse_lowlevel.h>
#include "fsroot.h"

static char root_path[PATH_MAX];
static unsigned int root_path_len;

int dm_fullpath(const char *in, char *out, size_t outlen)
{
#define FIRST_CHAR(v) (v[0])
#define LAST_CHAR(v) (v[v##_len - 1])
	char must_add_slash = 0, slash = '/';

	if (!in || !out || outlen == 0)
		return 0;

	size_t in_len = strlen(in);
	size_t ttl_len = root_path_len + in_len + 1;

	if (LAST_CHAR(root_path) != '/' && FIRST_CHAR(in) != '/') {
		ttl_len++;
		must_add_slash = 1;
	} else if (LAST_CHAR(root_path) == '/' && FIRST_CHAR(in) == '/') {
		in++;
		ttl_len--;
	}

	if (outlen < ttl_len)
		return 0;

	strcpy(out, root_path);
	if (must_add_slash)
		strncat(out, &slash, 1);
	strcat(out, in);

	fprintf(stderr, "DEBUG: fullpath = %s\n", out);
	return 1;
#undef FIRST_CHAR
#undef LAST_CHAR
}

static void *dm_fuse_init(struct fuse_conn_info *conn)
{
	printf("DroneFS device monitor. Written by Ander Juaristi.\n");

	if (fsroot_init(root_path) != FSROOT_OK) {
		fprintf(stderr, "ERROR: Could not initialize fsroot\n");
		exit(EXIT_FAILURE);
	}

	return NULL;
}

static void dm_fuse_destroy(void *v)
{
	fsroot_deinit();
}

/*
 * Get file attributes.
 */
static int dm_fuse_getattr(const char *path, struct stat *st)
{
	int retval = -EFAULT;

	if (!path || !st)
		return -EFAULT;
	if (!*path)
		return -ENOENT;

	switch (fsroot_getattr(path, st)) {
	case FSROOT_E_BADARGS:
		retval = -EFAULT;
		break;
	case FSROOT_E_NOTEXISTS:
		return -ENOENT;
		break;
	case FSROOT_E_SYSCALL:
		retval = -errno;
		break;
	case FSROOT_OK:
		retval = 0;
		break;
	}

	return retval;
}

/*
 * Create a file node.
 * This is called for all non-directory and non-symlink nodes.
 * If the create() method is defined, then for regular files that will be called instead.
 * TODO we just error out for non-regular files for now (symlinks and directories don't invoke this function)
 */
static int dm_fuse_mknod(const char *path, mode_t mode, dev_t dev)
{
	int retval = -EFAULT, err = 0;
	struct fuse_context *fctx;

	if (!path)
		return -EFAULT;
	if (!*path)
		return -ENOENT;
	if (!S_ISREG(mode))
		return -EACCES;

	fctx = fuse_get_context();
	if (!fctx)
		return -EFAULT;

	retval = fsroot_create(path, fctx->uid, fctx->gid, mode, 0, &err);

	if (retval == FSROOT_OK) {
		retval = fsroot_release(path);
//		retval = 0;
		goto end;
	}

	switch (retval) {
	case FSROOT_E_SYSCALL:
		retval = -err;
		break;
	case FSROOT_E_BADARGS:
		retval = -EFAULT;
		break;
	case FSROOT_E_EXISTS:
		retval = -ENOENT;
		break;
	default:
		retval = -EFAULT;
		break;
	}

end:
	return retval;
}

/*
 * Create a symbolic link.
 * Argument 'path' is where the link points, while 'link'
 * is the link itself.
 */
static int dm_fuse_symlink(const char *path, const char *link)
{
	int retval = -EFAULT;
	struct fuse_context *fctx;

	if (!path || !link)
		return -EFAULT;
	if (!*path || !*link)
		return -ENOENT;

	fctx = fuse_get_context();
	if (!fctx)
		return -EFAULT;

	retval = fsroot_symlink(link, path, fctx->uid, fctx->gid, 0120600);

	switch (retval) {
	case FSROOT_OK:
		retval = 0;
		break;
	case FSROOT_E_SYSCALL:
		/*
		 * FIXME TODO this should account for the specific case
		 * where 'link' already exists.
		 */
		retval = -EACCES;
		break;
	case FSROOT_E_BADARGS:
	case FSROOT_E_NOMEM:
		retval = -EFAULT;
		break;
	case FSROOT_E_EXISTS:
		retval = -EEXIST;
		break;
	}

	return retval;
}

static int dm_fuse_readlink(const char *path, char *buf, size_t buflen)
{
	int retval = -EFAULT;
	char *tmpbuf = NULL;
	size_t buflen_required = 0;

	if (!path || !buf)
		return -EFAULT;
	if (!*path)
		return -ENOENT;

	buflen_required = buflen;
	retval = fsroot_readlink(path, buf, &buflen_required);

	if (retval == FSROOT_E_NOMEM) {
		/* buflen_required now contains the minimum amount */
		char *tmpbuf = malloc(buflen_required);
		if (!tmpbuf)
			return -EFAULT;

		retval = fsroot_readlink(path, tmpbuf, &buflen_required);
	}

	if (retval == FSROOT_OK) {
		if (tmpbuf && buflen_required > 0) {
			/* Truncate the link target to the specified length */
			memcpy(buf, tmpbuf, buflen);
		}

		retval = 0;
	} else if (retval == FSROOT_E_BADARGS || retval == FSROOT_E_SYSCALL) {
		retval = -EFAULT;
	} else if (retval == FSROOT_E_NOTEXISTS) {
		retval = -ENOENT;
	}

	if (tmpbuf)
		free(tmpbuf);

	return retval;

}

/*
 * Create a directory.
 * Should resemble mkdir(2).
 * TODO check permissions for directories as well (hook through fsroot)
 */
static int dm_fuse_mkdir(const char *path, mode_t mode)
{
	int retval = -EFAULT;
	struct fuse_context *fctx;

	if (!path)
		return -EFAULT;
	if (!*path)
		return -ENOENT;

	fctx = fuse_get_context();
	if (!fctx)
		return -EFAULT;

	retval = fsroot_mkdir(path, fctx->uid, fctx->gid, mode);

	switch (retval) {
	case FSROOT_OK:
		retval = 0;
		break;
	case FSROOT_E_BADARGS:
	case FSROOT_E_SYSCALL:
		retval = -EFAULT;
		break;
	case FSROOT_E_EXISTS:
		retval = -EEXIST;
		break;
	}

	return retval;
}

/*
 * Remove a file.
 * TODO fsroot does not support unlink yet!
 */
static int dm_fuse_unlink(const char *path)
{
	/* TODO implement this */
	return -EFAULT;
}

/*
 * Remove a directory.
 */
static int dm_fuse_rmdir(const char *path)
{
	int retval = -EFAULT;

	if (!path)
		return -EFAULT;
	if (!*path)
		return -ENOENT;

	switch (fsroot_rmdir(path)) {
	case FSROOT_OK:
		retval = 0;
		break;
	case FSROOT_E_BADARGS:
	case FSROOT_E_SYSCALL:
		retval = -EFAULT;
		break;
	case FSROOT_E_NOTEXISTS:
		retval = -ENOENT;
		break;
	}

	return retval;
}

/*
 * Rename a file.
 * Should resemble rename(2).
 *
 * Verify these with unit tests:
 * FIXME TODO what happens if a user tries to make a directory a subdirectory of itself (-EINVAL) ?
 * FIXME TODO what happens if the directory is not empty?
 *
 * TODO what does 'foo' do?
 */
static int dm_fuse_rename(const char *path, const char *newpath)
{
	int retval = -EFAULT;

	if (!path || !newpath)
		return -EFAULT;
	if (!*path || !*newpath)
		return -ENOENT;

	retval = fsroot_rename(path, newpath);

	switch (retval) {
	case FSROOT_OK:
		retval = 0;
		break;
	case FSROOT_E_NOTEXISTS:
		retval = -ENOENT;
		break;
	case FSROOT_E_EXISTS:
		retval = -EEXIST;
		break;
	case FSROOT_E_BADARGS:
	case FSROOT_E_SYSCALL:
		retval = -EFAULT;
		break;
	}

	return retval;
}

/*
 * Change the permission bits of a file.
 * TODO implement. Hook through fsroot.
 */
static int dm_fuse_chmod(const char *path, mode_t mode)
{
	int retval = -EFAULT;

	if (!path)
		return -EFAULT;
	if (!*path)
		return -ENOENT;

	retval = fsroot_chmod(path, mode);

	switch (retval) {
	case FSROOT_OK:
		retval = 0;
		break;
	case FSROOT_E_BADARGS:
		retval = -EFAULT;
		break;
	case FSROOT_E_NOTEXISTS:
		retval = -ENOENT;
		break;
	}

	return retval;
}

/*
 * Change the owner and group of a file.
 * TODO implement. Hook through fsroot.
 */
static int dm_fuse_chown(const char *path, uid_t uid, gid_t gid)
{
	int retval = -EFAULT;

	if (!path)
		return -EFAULT;
	if (!*path)
		return -ENOENT;

	switch (fsroot_chown(path, uid, gid)) {
	case FSROOT_OK:
		retval = 0;
		break;
	case FSROOT_E_BADARGS:
		retval = -EFAULT;
		break;
	case FSROOT_E_NOTEXISTS:
		retval = -ENOENT;
		break;
	}

	return retval;
}

/*
 * Change the size of a file.
 * This should resemble truncate(2).
 * TODO fsroot does not yet support truncate!
 */
static int dm_fuse_truncate(const char *path, off_t newsize, struct fuse_file_info *fi)
{
	return -EFAULT;
}

/*
 * Open a file.
 * No creation (O_CREAT, O_EXCL) and by default also no truncation (O_TRUNC) flags
 * will be passed.
 * Unless the 'default_permissions' mount option is given, open should check
 * whether the operation is permitted for the given flags.
 */
static int dm_fuse_open(const char *path, struct fuse_file_info *fi)
{
	int fd, retval = -EFAULT;

	if (!path)
		return -EFAULT;
	if (!*path)
		return -ENOENT;

	retval = fsroot_open(path, fi->flags);

	if (retval >= 0) {
		/* Open succeeded and we've got a file descriptor */
		fi->fh = retval;
		retval = 0;
		goto end;
	}

	/* Handle the error condition */
	switch (retval) {
	case FSROOT_E_BADARGS:
		retval = -EFAULT;
		break;
	case FSROOT_E_NOTEXISTS:
		retval = -ENOENT;
		break;
	}

end:
	return retval;
}

static int dm_fuse_release(const char *path, struct fuse_file_info *fi)
{
	/* FUSE ignores the return value of this function, and so do we */
	if (path)
		fsroot_release(path);
	return 0;
}

/*
 * Read data from an open file.
 * Should return exactly the number of bytes requested except on EOF or error,
 * otherwise the rest of the data will be substituted with zeroes.
 * An exception to this is when the 'direct_io' mount option is specified,
 * in which case the return value of the read system call will reflect
 * the return value of this operation.
 */
static int dm_fuse_read(const char *path,
		char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	int retval = -EINVAL, err = 0;

	/* We don't even bother to check 'path', since we're not using it */
	if (!buf || !size)
		return -EFAULT;
	if (fi->fh < 0)
		return -EBADF;

	retval = fsroot_read(fi->fh, buf, size, offset, &err);

	switch (retval) {
	case FSROOT_E_BADARGS:
		retval = -EINVAL;
		break;
	case FSROOT_E_SYSCALL:
		retval = -err;
		break;
	}

	return retval;
}

/*
 * Write data to an open file.
 * Write should return exactly the number of bytes requested except on error.
 * An exception to this is when the 'direct_io' mount option is specified (see read operation).
 */
static int dm_fuse_write(const char *path,
		const char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	int retval = -EINVAL, err = 0;

	if (!buf || !size)
		return -EFAULT;
	if (fi->fh < 0)
		return -EBADF;

	retval = fsroot_write(fi->fh, buf, size, offset, &err);

	switch (retval) {
	case FSROOT_E_BADARGS:
		retval = -EINVAL;
		break;
	case FSROOT_E_SYSCALL:
		retval = -err;
		break;
	}

	return retval;
}

/*
 * Open directory.
 * Unless the 'default_permissions' mount option is given,
 * this method should check if opendir is permitted for this directory.
 * Optionally opendir may also return an arbitrary filehandle in the fuse_file_info structure,
 * which will be passed to readdir, closedir and fsyncdir.
 */
static int dm_fuse_opendir(const char *path, struct fuse_file_info *fi)
{
	DIR *dp;
	char fullpath[PATH_MAX];

	if (!path)
		return -EFAULT;
	if (!*path)
		return -ENOENT;
	if (!fi)
		return -EFAULT;

	dp = opendir(fullpath);
	fi->fh = (uintptr_t) dp;

	return (dp == NULL ? -1 : 0);
}

/*
 * Read directory
 *
 * The filesystem may choose between two modes of operation:
 *
 * 	1) The readdir implementation ignores the offset parameter,
 * 	and passes zero to the filler function's offset. The filler function
 * 	will not return '1' (unless an error happens), so the whole directory is
 * 	read in a single readdir operation.
 *
 * 	2) The readdir implementation keeps track of the offsets of the directory entries.
 * 	It uses the offset parameter and always passes non-zero offset to the filler function.
 * 	When the buffer is full (or an error happens) the filler function will return '1'.
 *
 * TODO implement: this basically requires iterating fsroot.
 */
static int dm_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	struct stat st;
//	struct fsroot_file file;
	int retval = 0;
	int initial_errno = errno;

	dp = (DIR *) (uintptr_t) fi->fh;
	de = readdir(dp);
	if (de == NULL) {
		retval = (errno == initial_errno ? 0 : -errno);
		goto end;
	}

	for (; de != NULL; de = readdir(dp)) {
		if (stat(de->d_name, &st) == -1) {
			retval = -errno;
			goto end;
		}

		if (!S_ISREG(st.st_mode)) {
			if (filler(buf, de->d_name, NULL, 0) != 0) {
				retval = -ENOMEM;
				goto end;
			}
		} else {
//			switch (fsroot_get_file(de->d_name, &file)) {
//			case 0:
//				/* TODO fsroot_get_file() should directly give us the 'stat' for this file */
//				if (filler(buf, de->d_name, NULL, 0) != 0) {
//					retval = -ENOMEM;
//					goto end;
//				}
//				break;
//			case FSROOT_E_LIBC:
//				retval = -errno;
//				goto end;
//				break;
//			default:
//				retval = -EFAULT;
//				goto end;
//				break;
//			}
		}
	}

	if (retval == 0 && errno != initial_errno)
		retval = -errno;

end:
	return retval;
}

/*
 * Check file access permissions.
 * This will be called for access(2), unless the 'default_permissions'
 * mount option is given.
 * TODO This function should be removed. We'll be invoking this daemon with 'default_permissions' set.
 */
static int dm_fuse_access(const char *path, int mask)
{
	return -EACCES;
}

void print_help()
{
	printf("<mount point> <root dir>\n");
}

int main(int argc, char **argv)
{
	struct fuse_args args;
	struct fuse_operations dm_operations = {
		.init           = dm_fuse_init,
		.destroy	= dm_fuse_destroy,
		.getattr	= dm_fuse_getattr,
		.symlink	= dm_fuse_symlink,
		.readlink	= dm_fuse_readlink,
		.mknod		= dm_fuse_mknod,
		.mkdir		= dm_fuse_mkdir,
//		.unlink		= dm_fuse_unlink,
		.rmdir		= dm_fuse_rmdir,
		.rename		= dm_fuse_rename,
		.chmod		= dm_fuse_chmod,
		.chown		= dm_fuse_chown,
//		.truncate	= dm_fuse_truncate,
		.open		= dm_fuse_open,
		.release	= dm_fuse_release,
		.read		= dm_fuse_read,
		.write		= dm_fuse_write,
//		.opendir	= dm_fuse_opendir,
//		.readdir	= dm_fuse_readdir,
//		.access		= dm_fuse_access
	};
	struct options {
		int show_help;
	} options = {0};
	const struct fuse_opt opts[] = {
		{"-h", offsetof(struct options, show_help), 1},
		{"--help", offsetof(struct options, show_help), 1},
		FUSE_OPT_END
	};

	if (argc < 3)
		goto help;

	/*
	 * The last argument should be the root directory.
	 * Strip it off.
	 */
	argc--;
	root_path_len = strlen(argv[argc]);
	if (root_path_len > sizeof(root_path) - 1) {
		fprintf(stderr, "ERROR: too large root path.\n");
		return 1;
	}
	strcpy(root_path, argv[argc]);

	args.argc = argc;
	args.argv = argv;
	args.allocated = 0;
	if (fuse_opt_parse(&args, &options, opts, NULL) == -1)
		return 1;

	if (options.show_help)
		goto help;

	return fuse_main(args.argc, args.argv, &dm_operations, NULL);

help:
	print_help();
	return 0;
}
