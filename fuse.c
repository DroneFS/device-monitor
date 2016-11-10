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
#include <string.h>
#include <linux/limits.h>
#include <unistd.h>	/* rmdir(2), stat(2), unlink(2), chown(2),... */
#include <sys/stat.h>	/* mkdir(2), chmod(2) */
#include <dirent.h>
#include <stddef.h>	/* offsetof() macro */
#include <errno.h>
#include <fuse.h>
#include <fuse_lowlevel.h>

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

static void *dm_fuse_init(struct fuse_conn_info *conn, struct fuse_config *cfg)
{
	printf("DroneFS device monitor. Written by Ander Juaristi.\n");
	return NULL;
}

/*
 * Get file attributes.
 */
static int dm_fuse_getattr(const char *path, struct stat *st, struct fuse_file_info *fi)
{
	int retval = 0;
	char fullpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;
	if (!st)
		return -EFAULT;

	retval = lstat(fullpath, st);
	return (retval == 0 ? retval : -errno);
}

/*
 * Create a file node.
 * This is called for all non-directory and non-symlink nodes.
 * If the create() method is defined, then for regular files that will be called instead.
 */
static int dm_fuse_mknod(const char *path, mode_t mode, dev_t dev)
{
	int retval = 0;
	char fullpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;
	if (!S_ISREG(mode))
		return -EACCES;

	struct fuse_context *ctx = fuse_get_context();

	retval = open(fullpath, O_CREAT | O_EXCL | O_WRONLY, mode);
	if (retval >= 0) {
		close(retval);
		retval = 0;
	} else if (retval == -1) {
		retval = -errno;
	}

	return retval;
}

/*
 * Create a symbolic link.
 * Argument 'path' is where the link points, while 'link'
 * is the link itself.
 */
static int dm_fuse_symlink(const char *path, const char *link)
{
	char full_link[PATH_MAX];

	if (!path || !link || !dm_fullpath(link, full_link, sizeof(full_link)))
		return -EFAULT;
	return (symlink(path, full_link) == 0 ? 0 : -errno);
}

static int dm_fuse_readlink(const char *path, char *buf, size_t buflen)
{
	size_t retval = 0;
	char fullpath[PATH_MAX];

	if (!path || !buf || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;

	retval = readlink(fullpath, buf, buflen - 1);
	if (retval >= 0) {
		buf[retval] = '\0';
		retval = 0;
	} else {
		memset(buf, 0, buflen);
		retval = -errno;
	}

	return retval;

}

/*
 * Create a directory.
 */
static int dm_fuse_mkdir(const char *path, mode_t mode)
{
	char fullpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;

	struct fuse_context *ctx = fuse_get_context();

	return mkdir(fullpath, mode);
}

/*
 * Remove a file.
 */
static int dm_fuse_unlink(const char *path)
{
	char fullpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;

	return unlink(fullpath);
}

/*
 * Remove a directory.
 */
static int dm_fuse_rmdir(const char *path)
{
	char fullpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;

	return rmdir(fullpath);
}

/*
 * Rename a file.
 */
static int dm_fuse_rename(const char *path, const char *newpath, unsigned int foo)
{
	char fullpath[PATH_MAX], full_newpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;
	if (!newpath || !dm_fullpath(newpath, full_newpath, sizeof(full_newpath)))
		return -EFAULT;

	return rename(fullpath, full_newpath);
}

/*
 * Change the permission bits of a file.
 */
static int dm_fuse_chmod(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	char fullpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;

	return chmod(fullpath, mode);
}

/*
 * Change the owner and group of a file.
 */
static int dm_fuse_chown(const char *path, uid_t uid, gid_t gid, struct fuse_file_info *fi)
{
	char fullpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;

	return chown(fullpath, uid, gid);
}

/*
 * Change the size of a file.
 */
static int dm_fuse_truncate(const char *path, off_t newsize, struct fuse_file_info *fi)
{
	char fullpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;

	return truncate(fullpath, newsize);
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
	int fd;
	char fullpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;

	fd = open(fullpath, fi->flags);
	if (fd < 0)
		return -1;

	fi->fh = fd;
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
static int dm_fuse_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	return pread(fi->fh, buf, size, offset);
}

/*
 * Write data to an open file.
 * Write should return exactly the number of bytes requested except on error.
 * An exception to this is when the 'direct_io' mount option is specified (see read operation).
 */
static int dm_fuse_write(const char *path, const char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	return pwrite(fi->fh, buf, size, offset);
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

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;
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
 */
static int dm_fuse_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags)
{
	DIR *dp;
	struct dirent *de;
	int initial_errno = errno;

	dp = (DIR *) (uintptr_t) fi->fh;
	de = readdir(dp);
	if (de == 0)
		return -1;

	do {
		if (filler(buf, de->d_name, NULL, 0,
				(flags == FUSE_READDIR_PLUS ? FUSE_FILL_DIR_PLUS : 0))
				!= 0)
			return -ENOMEM;
	} while ((de = readdir(dp)) != NULL);

	return (errno == initial_errno ? 0 : -1);
}

/*
 * Check file access permissions.
 * This will be called for access(2), unless the 'default_permissions'
 * mount option is given.
 */
static int dm_fuse_access(const char *path, int mask)
{
	char fullpath[PATH_MAX];

	if (!path || !dm_fullpath(path, fullpath, sizeof(fullpath)))
		return -EFAULT;

	return access(fullpath, mask);
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
		.getattr	= dm_fuse_getattr,
		.symlink	= dm_fuse_symlink,
		.readlink	= dm_fuse_readlink,
		.mknod		= dm_fuse_mknod,
		.mkdir		= dm_fuse_mkdir,
		.unlink		= dm_fuse_unlink,
		.rmdir		= dm_fuse_rmdir,
		.rename		= dm_fuse_rename,
		.chmod		= dm_fuse_chmod,
		.chown		= dm_fuse_chown,
		.truncate	= dm_fuse_truncate,
		.open		= dm_fuse_open,
		.read		= dm_fuse_read,
		.write		= dm_fuse_write,
		.opendir	= dm_fuse_opendir,
		.readdir	= dm_fuse_readdir,
		.access		= dm_fuse_access
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
