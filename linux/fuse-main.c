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
#include "fsroot.h"
#include "log.h"
#include "mm.h"

static char
	*config_file,
	*database_file;
static char root_path[PATH_MAX];
static unsigned int root_path_len;
struct {
	uid_t uid;
	gid_t gid;
} root_info;
struct m_fuse_ctx {
	fsroot_t *fs;
	struct logger *l;
};

static struct m_fuse_ctx *__get_fsroot_ctx()
{
	struct fuse_context *fctx = fuse_get_context();

	if (fctx)
		return (struct m_fuse_ctx *) fctx->private_data;
	else
		return NULL;
}

static void *dm_fuse_init(struct fuse_conn_info *conn)
{
	int retval;
	struct m_fuse_ctx *ctx = NULL;
	fsroot_t *fsroot = NULL;
	struct logger *logger = NULL;

	log_init(&logger);
	log_set_stream(logger, LOG_INFO, stderr);
	log_set_stream(logger, LOG_DEBUG, stderr);
	log_set_stream(logger, LOG_ERROR, stderr);

	log_i(logger, "DroneFS device monitor. Written by Ander Juaristi.\n");

	if ((retval = fsroot_init(&fsroot, logger)) != S_OK) {
		fprintf(stderr, "ERROR: Could not initialize fsroot\n");
		goto error;
	}

	if ((retval = fsroot_set_root_directory(fsroot, root_path)) != S_OK) {
		fprintf(stderr, "ERROR: Could not set root directory (%s)\n", error2str(retval));
		goto error;
	}

	if (!config_file) {
		fprintf(stderr, "WARNING: Config file not set\n");
	} else if ((retval = fsroot_set_config_file(fsroot, config_file)) != S_OK) {
		fprintf(stderr, "ERROR: Could not set config file (%s)\n", error2str(retval));
		goto error;
	}

	if (!database_file) {
		fprintf(stderr, "WARNING: Database file not set\n");
	} else if ((retval = fsroot_set_database_file(fsroot, database_file)) != S_OK) {
		fprintf(stderr, "ERROR: Could not set database file (%s)\n", error2str(retval));
		goto error;
	}

	if ((retval = fsroot_start(fsroot, root_info.uid, root_info.gid, /* rwxr-xr-- */ 0040754)) != S_OK) {
		fprintf(stderr, "ERROR: Could not start fsroot (%s)\n", error2str(retval));
		goto error;
	}

	ctx = mm_new0(struct m_fuse_ctx);
	ctx->fs = fsroot;
	ctx->l = logger;
	return ctx;

error:
	if (fsroot)
		fsroot_deinit(&fsroot);
	if (logger)
		log_deinit(&logger);
	exit(EXIT_FAILURE);
}

static void dm_fuse_destroy(void *v)
{
	int retval;
	struct m_fuse_ctx *ctx = (struct m_fuse_ctx *) v;

	if (!database_file)
		goto end;
	if ((retval = fsroot_persist(ctx->fs, database_file)) != S_OK) {
		fprintf(stderr, "ERROR: Could not store FSRoot state at file '%s'"
			"Error code: %d", database_file, retval);
	}

end:
	fsroot_deinit(&ctx->fs);
	log_deinit(&ctx->l);
}

/*
 * Get file attributes.
 */
static int dm_fuse_getattr(const char *path, struct stat *st)
{
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT;

	if (!path || !st || !(ctx = __get_fsroot_ctx()))
		return -EFAULT;
	if (!*path)
		return -ENOENT;
	fs = ctx->fs;

	switch (fsroot_getattr(fs, path, st)) {
	case E_BADARGS:
		retval = -EFAULT;
		break;
	case E_NOTEXISTS:
		return -ENOENT;
		break;
	case E_SYSCALL:
		retval = -errno;
		break;
	case S_OK:
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
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT, err = 0;
	struct fuse_context *fctx;

	if (!path)
		return -EFAULT;
	if (!*path)
		return -ENOENT;
	if (!S_ISREG(mode))
		return -EACCES;

	fctx = fuse_get_context();
	if (!fctx || !(ctx = (struct m_fuse_ctx *) fctx->private_data))
		return -EFAULT;
	fs = ctx->fs;

	retval = fsroot_create(fs, path, fctx->uid, fctx->gid, mode, 0, &err);

	if (retval >= 0) {
		retval = fsroot_release(fs, path);
//		retval = 0;
		goto end;
	}

	switch (retval) {
	case E_SYSCALL:
		retval = -err;
		break;
	case E_BADARGS:
		retval = -EFAULT;
		break;
	case E_EXISTS:
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
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT;
	struct fuse_context *fctx;

	if (!path || !link)
		return -EFAULT;
	if (!*path || !*link)
		return -ENOENT;

	fctx = fuse_get_context();
	if (!fctx || !(ctx = (struct m_fuse_ctx *) fctx->private_data))
		return -EFAULT;
	fs = ctx->fs;

	retval = fsroot_symlink(fs, link, path, fctx->uid, fctx->gid, 0120600);

	switch (retval) {
	case S_OK:
		retval = 0;
		break;
	case E_SYSCALL:
		/*
		 * FIXME TODO this should account for the specific case
		 * where 'link' already exists.
		 */
		retval = -EACCES;
		break;
	case E_BADARGS:
	case E_NOMEM:
		retval = -EFAULT;
		break;
	case E_EXISTS:
		retval = -EEXIST;
		break;
	}

	return retval;
}

static int dm_fuse_readlink(const char *path, char *buf, size_t buflen)
{
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT;
	char *tmpbuf = NULL;
	size_t buflen_required = 0;

	if (!path || !buf || !(ctx = __get_fsroot_ctx()))
		return -EFAULT;
	if (!*path)
		return -ENOENT;
	fs = ctx->fs;

	buflen_required = buflen;
	retval = fsroot_readlink(fs, path, buf, &buflen_required);

	if (retval == E_NOMEM) {
		/* buflen_required now contains the minimum amount */
		char *tmpbuf = malloc(buflen_required);
		if (!tmpbuf)
			return -EFAULT;

		retval = fsroot_readlink(fs, path, tmpbuf, &buflen_required);
	}

	if (retval == S_OK) {
		if (tmpbuf && buflen_required > 0) {
			/* Truncate the link target to the specified length */
			memcpy(buf, tmpbuf, buflen);
		}

		retval = 0;
	} else if (retval == E_BADARGS || retval == E_SYSCALL) {
		retval = -EFAULT;
	} else if (retval == E_NOTEXISTS) {
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
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT;
	struct fuse_context *fctx;

	if (!path)
		return -EFAULT;
	if (!*path)
		return -ENOENT;

	fctx = fuse_get_context();
	if (!fctx || !(ctx = (struct m_fuse_ctx *) fctx->private_data))
		return -EFAULT;
	fs = ctx->fs;

	retval = fsroot_mkdir(fs, path, fctx->uid, fctx->gid, 0040000 | mode);

	switch (retval) {
	case S_OK:
		retval = 0;
		break;
	case E_BADARGS:
	case E_SYSCALL:
		retval = -EFAULT;
		break;
	case E_EXISTS:
		retval = -EEXIST;
		break;
	}

	return retval;
}

/*
 * Remove a directory.
 */
static int dm_fuse_rmdir(const char *path)
{
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT;

	if (!path || !(ctx = __get_fsroot_ctx()))
		return -EFAULT;
	if (!*path)
		return -ENOENT;
	fs = ctx->fs;

	switch (fsroot_rmdir(fs, path)) {
	case S_OK:
		retval = 0;
		break;
	case E_BADARGS:
	case E_SYSCALL:
		retval = -EFAULT;
		break;
	case E_NOTEXISTS:
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
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT;

	if (!path || !newpath || !(ctx = __get_fsroot_ctx()))
		return -EFAULT;
	if (!*path || !*newpath)
		return -ENOENT;
	fs = ctx->fs;

	retval = fsroot_rename(fs, path, newpath);

	switch (retval) {
	case S_OK:
		retval = 0;
		break;
	case E_NOTEXISTS:
		retval = -ENOENT;
		break;
	case E_EXISTS:
		retval = -EEXIST;
		break;
	case E_BADARGS:
	case E_SYSCALL:
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
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT;

	if (!path || !(ctx = __get_fsroot_ctx()))
		return -EFAULT;
	if (!*path)
		return -ENOENT;
	fs = ctx->fs;

	retval = fsroot_chmod(fs, path, mode);

	switch (retval) {
	case S_OK:
		retval = 0;
		break;
	case E_BADARGS:
		retval = -EFAULT;
		break;
	case E_NOTEXISTS:
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
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT;

	if (!path || !(ctx = __get_fsroot_ctx()))
		return -EFAULT;
	if (!*path)
		return -ENOENT;
	fs = ctx->fs;

	switch (fsroot_chown(fs, path, uid, gid)) {
	case S_OK:
		retval = 0;
		break;
	case E_BADARGS:
		retval = -EFAULT;
		break;
	case E_NOTEXISTS:
		retval = -ENOENT;
		break;
	}

	return retval;
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
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT;

	if (!path || !(ctx = __get_fsroot_ctx()))
		return -EFAULT;
	if (!*path)
		return -ENOENT;
	fs = ctx->fs;

	retval = fsroot_open(fs, path, fi->flags);

	if (retval >= 0) {
		/* Open succeeded and we've got a file descriptor */
		fi->fh = retval;
		retval = 0;
		goto end;
	}

	/* Handle the error condition */
	switch (retval) {
	case E_BADARGS:
		retval = -EFAULT;
		break;
	case E_NOTEXISTS:
		retval = -ENOENT;
		break;
	}

end:
	return retval;
}

static int dm_fuse_release(const char *path, struct fuse_file_info *fi)
{
	fsroot_t *fs;
	struct m_fuse_ctx *ctx = __get_fsroot_ctx();

	if (!ctx)
		return -EFAULT;
	fs = ctx->fs;
	if (!fs)
		return -EFAULT;

	/* FUSE ignores the return value of this function, and so do we */
	if (path)
		fsroot_release(fs, path);
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
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EINVAL, err = 0;

	/* We don't even bother to check 'path', since we're not using it */
	if (!buf || !size || !(ctx = __get_fsroot_ctx()))
		return -EFAULT;
	if (fi->fh < 0)
		return -EBADF;
	fs = ctx->fs;

	retval = fsroot_read(fs, fi->fh, buf, size, offset, &err);

	switch (retval) {
	case E_BADARGS:
		retval = -EINVAL;
		break;
	case E_SYSCALL:
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
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EINVAL, err = 0;

	if (!buf || !size || !(ctx = __get_fsroot_ctx()))
		return -EFAULT;
	if (fi->fh < 0)
		return -EBADF;
	fs = ctx->fs;

	retval = fsroot_write(fs, fi->fh, buf, size, offset, &err);

	switch (retval) {
	case E_BADARGS:
		retval = -EINVAL;
		break;
	case E_SYSCALL:
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
	fsroot_t *fs;
	struct m_fuse_ctx *ctx;
	int retval = -EFAULT, err = 0;
	void *dir_handle = NULL;

	if (!path || !(ctx = __get_fsroot_ctx()))
		return -EFAULT;
	if (!*path)
		return -ENOENT;
	if (!fi)
		return -EFAULT;
	fs = ctx->fs;

	switch (fsroot_opendir(fs, path, &dir_handle, &err)) {
	case E_BADARGS:
		retval = -EFAULT;
		break;
	case E_SYSCALL:
		retval = -err;
		break;
	case E_NOTEXISTS:
		retval = -ENOENT;
		break;
	case S_OK:
		/*
		 * opendir() was successful, so we store the handle
		 * for future calls to readdir(), closedir(), etc.
		 */
		fi->fh = (uintptr_t) dir_handle;
		retval = 0;
		break;
	}

	return retval;
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
 */
static int dm_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi)
{
	void *dir_handle = (void *) fi->fh;
	char dir_path[PATH_MAX];
	int retval = -EFAULT, err = 0;

	do {
		/* Iterate until there are no more entries */
		retval = fsroot_readdir(dir_handle, dir_path, sizeof(dir_path), &err);
		if (retval < 0) {
			if (retval == E_SYSCALL)
				retval = -err;
			goto end;
		}

		if (retval != S_NOMORE) {
			/* We've got an entry. Pass it over to FUSE. */
			if (filler(buf, dir_path, NULL, 0) != 0) {
				retval = -ENOMEM;
				goto end;
			}
		}
	} while (retval != S_NOMORE);

	/* Everything went fine */
	retval = 0;

end:
	return retval;
}

static int dm_fuse_releasedir(const char *path, struct fuse_file_info *fi)
{
	if (!fi->fh)
		return -EFAULT;

	fsroot_closedir((void **) &fi->fh);
	return 0;
}

void print_help(const char *program_name)
{
	printf("Usage: %s [options] <mount point> <root dir>\n\n"
			"Available options:\n\n"
			"-h, --help    Show this help text\n"
			"--db-file     Set the path to the database file.\n"
			"              If the file does not exist, it will be created.\n"
			"--config-file Set the path to the configuration file.\n", program_name);
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
		.opendir	= dm_fuse_opendir,
		.readdir	= dm_fuse_readdir,
		.releasedir	= dm_fuse_releasedir
//		.access		= dm_fuse_access
	};
	struct options {
		int show_help;
		char *db_file;
		char *config_file;
	} options = {0};
	const struct fuse_opt opts[] = {
		{"-h", offsetof(struct options, show_help), 1},
		{"--help", offsetof(struct options, show_help), 1},
		{"--db-file=%s", offsetof(struct options, db_file), 0},
		{"--config-file=%s", offsetof(struct options, config_file), 0},
		FUSE_OPT_END
	};

	if (argc < 2)
		goto help;

	/* TODO FIXME do not hardcode these */
	root_info.uid = 1000;
	root_info.gid = 1000;

	args.argc = argc;
	args.argv = argv;
	args.allocated = 0;
	if (fuse_opt_parse(&args, &options, opts, NULL) == -1)
		return 1;

	/* Set the config file path */
	config_file = options.config_file;
	/* Set the database file path */
	database_file = options.db_file;

	/* The next argument is the root directory - we strip it off */
	args.argc--;
	root_path_len = strlen(args.argv[args.argc]);
	if (root_path_len > sizeof(root_path) - 1) {
		fprintf(stderr, "ERROR: too large root path.\n");
		return 1;
	}
	strcpy(root_path, args.argv[args.argc]);

	return fuse_main(args.argc, args.argv, &dm_operations, NULL);

help:
	print_help(argv[0]);
	return 0;
}
