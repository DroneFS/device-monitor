/*
 * fsroot.c
 *
 *  Created on: 18 Nov 2016
 *      Author: Ander Juaristi
 */
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <linux/limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>
#include "fsroot.h"

#include "chall/configuration.h"
#include "chall/formatter-xml.h"
#include "chall/crypto.h"
#include "fsroot-internal.h"
#include "fsroot-db.h"
#include "hash.h"
#include "log.h"
#include "mm.h"

/**
 * \file
 * \brief fsroot core functions
 * \defgroup fsroot fsroot core functions
 *
 * @{
 */
struct fsroot_file_descriptor {
	int8_t can_read,
		can_write,
		deleted;
	struct fsroot_file *file;
};

struct fsroot_open_files {
	struct fsroot_file_descriptor **file_descriptors;
	size_t num_files;
	size_t num_slots;
#define OPEN_FILES_INITIAL_NUM_SLOTS 5
	pthread_rwlock_t rwlock;
};

struct _fsroot_st
{
	int started;
	config_t *c;
	crypto_t *fs_crypto;
	struct logger *logger;
	char root_path[PATH_MAX + 1];
	char *database_file;
	struct hash_table *files;
	struct fsroot_open_files open_files;
};

typedef int (* challenge_loader_fn_t) (crypto_t *, const char *);

static int fsroot_fullpath(const char *root_path, const char *in, char *out, size_t outlen)
{
#define FIRST_CHAR(v) (v[0])
#define LAST_CHAR(v, len) (v[len - 1])
	char must_add_slash = 0, slash = '/';

	if (!in || !out || outlen == 0)
		return 0;

	size_t in_len = strlen(in),
	       root_path_len = strlen(root_path);
	size_t ttl_len = root_path_len + in_len + 1;

	if (LAST_CHAR(root_path, root_path_len) != '/' && FIRST_CHAR(in) != '/') {
		ttl_len++;
		must_add_slash = 1;
	} else if (LAST_CHAR(root_path, root_path_len) == '/' && FIRST_CHAR(in) == '/') {
		in++;
		ttl_len--;
	}

	if (outlen < ttl_len)
		return 0;

	strcpy(out, root_path);
	if (must_add_slash)
		strncat(out, &slash, 1);
	strcat(out, in);

	return 1;
#undef FIRST_CHAR
#undef LAST_CHAR
}

static int fsroot_create_file_buffer(fsroot_t *fs, struct fsroot_file *file, int *error_out)
{
	file_reader_t *r = NULL;
	off_t offset;
	uint8_t *decrypted = NULL;
	size_t decrypted_len = 0, buffer_len;

	FILE *fp = fopen(file->path, "r");
	if (fp == NULL)
		goto error;

	file->buf = NULL;
	file->buf_len = 0;

	if (feof(fp))
		/* File is empty. Return an empty buffer. */
		goto end;

	fseek(fp, 0, SEEK_END);
	offset = ftell(fp);
	if (offset == -1)
		goto error;
	if (offset == 0)
		goto end;

	fseek(fp, 0, SEEK_SET);

	file->buf = mm_new0n(offset);
	file->buf_len = fread(file->buf, 1, offset, fp);
	if (file->buf_len == -1)
		goto error;

	if (crypto_num_challenges_loaded(fs->fs_crypto) == 0 && fs->c) {
		/* Load challenges */
		if (crypto_load_challenges_from_config(fs->fs_crypto, fs->c) < 0)
			goto error;
	}

	if (crypto_num_challenges_loaded(fs->fs_crypto) > 0) {
		/*
		 * I'd rather not even try to deal with partial ciphertext.
		 * Just fail if we read fewer bytes than expected.
		 */
		if (file->buf_len < offset)
			goto error;

		r = create_xml_reader(file->path);
		if (!r)
			goto error;

		if (r->start_document(r, (const uint8_t *) file->buf, file->buf_len) != S_OK)
			goto error;

		decrypted_len = r->get_plaintext_length(r);
		if (!decrypted_len)
			goto error;

		buffer_len = decrypted_len;
		decrypted = crypto_create_plaintext_buffer(fs->fs_crypto, &buffer_len);
		if (!decrypted)
			goto error;

		if (crypto_decrypt_with_challenges(fs->fs_crypto, r,
				(const uint8_t *) file->buf, (size_t) file->buf_len,
				decrypted, buffer_len) != S_OK) {
			destroy_xml_reader(r);
			goto error;
		}

		if (r->end_document(r) != S_OK)
			goto error;

		/* Replace the original file contents with the decrypted contents */
		mm_free(file->buf);
		file->buf = (char *) decrypted;
		file->buf_len = decrypted_len;

		destroy_xml_reader(r);
	} else {
		log_i(fs->logger, "WARNING: No challenges were loaded. Data will be read as plaintext.\n");

		/* No challenges to load, so no need to decrypt - we've read the plaintext itself */
		if (file->buf_len < offset) {
			/*
			 * For some reason, we happened to read fewer bytes than expected
			 * so resize the buffer
			 */
			file->buf = mm_realloc(file->buf, file->buf_len);
		}
	}

end:
	fclose(fp);
	return 0;

error:
	if (decrypted)
		mm_free(decrypted);
	if (file->buf)
		mm_free(file->buf);
	if (fp)
		fclose(fp);
	if (error_out)
		*error_out = errno;
	destroy_xml_reader(r);
	return -1;
}

/*
 * Returns a negative number on error,
 * or else the file descriptor.
 * FIXME Maybe on Android we should not allocate a PATH_MAX chunk
 */
static struct fsroot_file *fsroot_create_file(fsroot_t *fs, const char *path, uid_t uid, gid_t gid, mode_t mode)
{
	struct fsroot_file *file = mm_new0(struct fsroot_file);
	char *fullpath = mm_new0n(PATH_MAX);

	if (!fsroot_fullpath(fs->root_path, path, fullpath, PATH_MAX)) {
		mm_free(fullpath);
		mm_free(file);
		goto end;
	}

	log_d(fs->logger, "fullpath: %s\n", fullpath);

	file->path = fullpath;
	file->uid = uid;
	file->gid = gid;
	file->mode = mode;

end:
	return file;
}

static int fsroot_sync_file(fsroot_t *fs, struct fsroot_file *file)
{
	int retval = S_OK, fd;
	file_formatter_t *fmt = NULL;
	uint8_t *encrypted = NULL;
	size_t encrypted_len = 0;
	ssize_t written;

	/* If file has no buffer, it has already been synced */
	if (!file->buf)
		goto end;

	fd = open(file->path, O_WRONLY | O_EXCL);
	if (fd == -1) {
		retval = E_SYSCALL;
		goto end;
	}

	if (crypto_num_challenges_loaded(fs->fs_crypto) == 0 && fs->c) {
		/* Load challenges */
		if (crypto_load_challenges_from_config(fs->fs_crypto, fs->c) < 0)
			return E_SYSCALL;
	}

	/* Create our file formatter, to save the output */
	fmt = create_xml_formatter();
	if (!fmt) {
		retval = E_UNKNOWN;
		goto end;
	}

	if (fmt->start_document(fmt) != S_OK) {
		retval = E_SYSCALL;
		goto end;
	}

	fmt->set_file_name(fmt, file->path);
	fmt->set_version(fmt, 1);
	fmt->set_plaintext_length(fmt, file->buf_len);

	pthread_rwlock_rdlock(&file->rwlock);

	if (crypto_num_challenges_loaded(fs->fs_crypto) > 0) {
		retval = crypto_encrypt_with_challenges(
			fs->fs_crypto, fmt,
			(const uint8_t *) file->buf, file->buf_len,
			&encrypted, &encrypted_len);

		if (retval != S_OK)
			goto end;

		retval = fmt->set_ciphertext(fmt, encrypted, encrypted_len);
		if (retval != S_OK)
			goto end;
	} else {
		log_i(fs->logger, "WARNING: No challenges were loaded. Data will be written as plaintext.\n");
		written = write(fd, file->buf, file->buf_len);
	}

	pthread_rwlock_unlock(&file->rwlock);

	written = fmt->end_document(fmt, fd);

	fsync(fd);
	close(fd);

	mm_free(encrypted);
	file->flags.is_synced = 1;

	if (written < 0)
		retval = E_SYSCALL;

end:
	destroy_xml_formatter(fmt);
	return retval;
}

static size_t __fsroot_open(struct fsroot_open_files *open_files, struct fsroot_file *file, int flags)
{
	struct fsroot_file_descriptor *fildes = mm_new0(struct fsroot_file_descriptor);
	size_t retval;

	if ((flags & O_WRONLY) == O_WRONLY) {
		fildes->can_write = 1;
	} else if ((flags & O_RDWR) == O_RDWR) {
		fildes->can_read = 1;
		fildes->can_write = 1;
	} else {
		/* O_RDONLY is 0, which means you can always read */
		fildes->can_read = 1;
	}

	fildes->file = file;

	/*
	 * Finally, add the file descriptor to the array of open files,
	 * resizing the array if needed.
	 */
	pthread_rwlock_wrlock(&open_files->rwlock);
	if (open_files->num_files == open_files->num_slots) {
		open_files->num_slots <<= 1;
		/* FIXME: if mm_reallocn() fails, the lock remains held (handle this in the no-mem callback) */
		open_files->file_descriptors = mm_reallocn(open_files->file_descriptors,
				open_files->num_slots,
				sizeof(struct fsroot_file_descriptor *));
	}

	open_files->file_descriptors[open_files->num_files] = fildes;
	retval = open_files->num_files++;
	pthread_rwlock_unlock(&open_files->rwlock);

	return retval;
}

/*
 * Returns the number of file descriptors that were referring to
 * the file.
 */
static unsigned int __fsroot_close(fsroot_t *fs, struct fsroot_file *file)
{
	struct fsroot_file_descriptor *fildes, **file_descriptors;
	struct fsroot_open_files *open_files = &fs->open_files;
	unsigned int num_files = 0, num_deleted_files = 0;

	pthread_rwlock_wrlock(&open_files->rwlock);
	/*
	 * Walk through all the file descriptors
	 * and mark as deleted those that refer to this file.
	 */
	for (unsigned int i = 0; i < open_files->num_files; i++) {
		fildes = open_files->file_descriptors[i];
		if (fildes->file == file) {
			fildes->deleted = 1;
			num_deleted_files++;
		}
	}

	if (num_deleted_files == 0)
		goto end;

	file_descriptors = mm_new(open_files->num_slots,
			struct fsroot_file_descriptor *);

	/*
	 * Copy all the non-deleted file descriptors to the new array,
	 * and free the deleted ones.
	 */
	for (unsigned int i = 0; i < open_files->num_files; i++) {
		fildes = open_files->file_descriptors[i];
		if (!fildes->deleted)
			file_descriptors[num_files++] = fildes;
		else
			mm_free(fildes);
	}

	mm_free(open_files->file_descriptors);
	open_files->file_descriptors = file_descriptors;
	open_files->num_files = num_files;

	pthread_rwlock_unlock(&open_files->rwlock);

	/* If there are no open files left, unload all the challenges */
	crypto_unload_all_challenges(fs->fs_crypto);

end:
	return num_deleted_files;
}

static int __fsroot_release(fsroot_t *fs, struct fsroot_file *file, char strict)
{
	if (!__fsroot_close(fs, file) && strict)
		return E_NOTOPEN;

	if (file->buf) {
		pthread_rwlock_wrlock(&file->rwlock);
		if (file->buf) {
			mm_free(file->buf);
			file->buf_len = 0;
		}
		pthread_rwlock_unlock(&file->rwlock);
	}

	return S_OK;
}

/**
 * \param[in] path Relative path to a file
 * \param[in] uid UID of the owner
 * \param[in] gid GID of the owner
 * \param[in] mode File mode (`mode_t`)
 * \param[in] flags File creation flags (see `open(2)`)
 * \param[out] error_out pointer to an integer where the value of `errno` will be placed, on error
 * \return a positive or zero file descriptor to the created file on success, or a negative integer on error
 *
 * Creates a new file and opens it, as if it was followed by a call to fsroot_open().
 *
 * \p path must not exist with fsroot. If an existing path is passed, fsroot_create() returns
 * immediately `FSROOT_E_EXISTS` and goes no further.
 *
 * \p mode should specify a regular file. Non-regular files, such as symlinks, directories or TTYs
 * will be rejected, causing fsroot_create() to return `FSROOT_E_BADARGS`.
 *
 * If the call to the underlying OS services fails, or if some invalid flags are passed that otherwise
 * prevent this function from running correctly (such as passing the `O_DIRECTORY` flag), `FSROOT_E_SYSCALL`
 * is returned, and the value of the `errno` variable will be placed in the memory pointed to by \p error_out,
 * if provided.
 *
 * The following flags are invalid, and will cause fsroot_create() to return `FSROOT_E_SYSCALL`:
 *  - O_ASYNC
 *  - O_DIRECTORY
 *  - O_NOCTTY
 *  - O_NOFOLLOW
 */
int fsroot_create(fsroot_t *fs, const char *path, uid_t uid, gid_t gid, mode_t mode, int flags, int *error_out)
{
	int error = 0, retval = S_OK, fd;
	struct fsroot_file *file;

	if (!fs || !path || !mode || !S_ISREG(mode))
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;
	if (hash_table_contains(fs->files, path))
		return E_EXISTS;

	/* These flags are not valid, and we'll return an error if we find them */
	if ((flags & O_ASYNC) == O_ASYNC) {
		error = EINVAL;
		retval = E_SYSCALL;
	} else if ((flags & O_DIRECTORY) == O_DIRECTORY) {
		/*
		 * fsroot_create() is only used for regular files.
		 * Directories are opened with fsroot_opendir().
		 */
		error = ENOTDIR;
		retval = E_SYSCALL;
	} else if ((flags & O_NOCTTY) == O_NOCTTY) {
		error = EINVAL;
		retval = E_SYSCALL;
	} else if ((flags & O_NOFOLLOW) == O_NOFOLLOW) {
		/* FIXME: O_NOFOLLOW should be ignored if O_PATH is present */
		error = ELOOP;
		retval = E_SYSCALL;
	}

	if (retval != S_OK)
		goto end;

	file = fsroot_create_file(fs, path, uid, gid, mode);
	if (!file) {
		error = EINVAL;
		retval = E_SYSCALL;
		goto end;
	}
	/*
	 * These flags will be handled internally:
	 * 	- O_EXCL
	 * 	- O_APPEND
	 * 	- O_DSYNC
	 * 	- O_SYNC
	 * 	- O_TMPFILE
	 *
	 * Thus, if they're present in 'flags', we strip them out.
	 *
	 * We also strip out O_EXCL and O_CREAT, since we pass them to open(2) anyway.
	 */
	if ((flags & O_EXCL) == O_EXCL)
		flags ^= O_EXCL;
	if ((flags & O_CREAT) == O_CREAT)
		flags ^= O_CREAT;
//	TODO this is not needed since we're not handling file offsets ourselves in the end
//	if (flags & O_APPEND == O_APPEND) {
//		flags ^= O_APPEND;
//		file->flags.append = 1;
//	}
	/*
	 * FIXME
	 * The difference between O_SYNC and O_DSYNC is that the former also writes
	 * file metadata. We're leaving this for later and treat both identically,
	 * as we're keeping all file metadata in memory for now.
	 */
#ifdef O_DSYNC
	if ((flags & O_DSYNC) == O_DSYNC) {
		flags ^= O_DSYNC;
		file->flags.sync = 1;
	}
#endif
#ifdef O_SYNC
	/* In Linux, O_SYNC is equivalent to O_RSYNC */
	if ((flags & O_SYNC) == O_SYNC) {
		flags ^= O_SYNC;
		file->flags.sync = 1;
	}
#endif
#ifdef O_TMPFILE
	if (flags & O_TMPFILE == O_TMPFILE) {
		flags ^= O_TMPFILE;
		file->flags.tmpfile = 1;
	}
#endif

	/* Now issue the system call */
	fd = open(file->path, O_CREAT | O_EXCL | flags, 0100600);
	if (fd == -1) {
		error = errno;
		retval = E_SYSCALL;
		goto end;
	}

	/*
	 * File was correctly created.
	 * We now register it in our hash table and close
	 * the real file.
	 */
	close(fd);
	hash_table_put(fs->files, strdup(path), file);

end:
	/*
	 * Finally, if the file was correctly created,
	 * generate a file descriptor for it.
	 */
	if (retval == S_OK) {
		retval = __fsroot_open(&fs->open_files, file, flags);
	} else if (retval == E_SYSCALL) {
		if (error != 0 && error_out)
			*error_out = error;
		if (file) {
			mm_free(file->path);
			mm_free(file);
		}
	}

	return retval;
}

/**
 * \param[in] path Relative path to a file
 * \param[in] flags Flags (see `open(2)`)
 * \return a positive file descriptor on success, or a negative integer on error
 *
 * \p path must specify an already existing file. If the file does not exist,
 * fsroot_open() immediately returns `FSROOT_E_NOTEXISTS` and goes no further.
 *
 * This function does not create new files. Use fsroot_create() for that instead.
 * This function will not complain if file creation (`O_CREAT`, `O_EXCL` )
 * or truncation (`O_TRUNC`) flags are passed, but they will be completely ignored.
 */
int fsroot_open(fsroot_t *fs, const char *path, int flags)
{
	struct fsroot_file *file;

	if (!fs || !path)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	/* File must exist, due to a previous call to fsroot_create() */
	file = hash_table_get(fs->files, path);
	if (!file || !S_ISREG(file->mode))
		return E_NOTEXISTS;

	return __fsroot_open(&fs->open_files, file, flags);
}

/**
 * \param[in] fd a valid file descriptor, obtained by a previous call to fsroot_create() or fsroot_open()
 * \param[out] buf pointer to a buffer where the read data will be placed
 * \param[in] size number of bytes to read
 * \param[in] offset offset to start reading from
 * \param[out] error_out pointer to an integer where the value of `errno` will be placed, on error
 * \return the number of bytes read, or a negative error code on error
 *
 * This function will read up to \p size bytes from the file referred to by file descriptor \p fd
 * starting at offset \p offset, and place the content in the buffer pointed to by \p buf.
 * The caller must supply a buffer of at least \p size length.
 *
 * This function returns the number of bytes read from the file and placed into \p buf,
 * which might be less than \p size. This should happen when the end of the file is reached
 * before \p size bytes were read. If this happens, `FSROOT_EOF` will be placed in \p error_out
 * (even though a positive number was returned).
 *
 * If the file was not open for reading (neither `O_RDONLY` nor `O_RDWR` were passed to
 * fsroot_create() or fsroot_open()) then `FSROOT_E_SYSCALL` will be returned and \p error_out
 * will be set to `EBADF`. If an error happens in some of the underlying OS services, `FSROOT_E_SYSCALL`
 * is returned and \p error_out is set to the value of `errno`.
 *
 * If an error happens, \p buf will not be modified in any way.
 */
int fsroot_read(fsroot_t *fs, int fd, char *buf, size_t size, off_t offset, int *error_out)
{
	int retval, error = 0;
	unsigned int idx;
	struct fsroot_file *file;
	struct fsroot_file_descriptor *fildes;

	if (!fs || !buf || !size || fd < 0)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	pthread_rwlock_rdlock(&fs->open_files.rwlock);

	if (fd >= fs->open_files.num_files) {
		pthread_rwlock_unlock(&fs->open_files.rwlock);
		return E_BADARGS;
	}

	/*
	 * TODO maybe we should add additional sanity checks here,
	 * like checking the PID of the reader.
	 */
	fildes = fs->open_files.file_descriptors[fd];
	pthread_rwlock_unlock(&fs->open_files.rwlock);

	if (!fildes->can_read) {
		/* ERROR: this file was not open for reading */
		retval = E_SYSCALL;
		error = EBADF;
		goto end;
	}
	file = fildes->file;

	if (file->buf == NULL) {
		pthread_rwlock_wrlock(&file->rwlock);
		if (file->buf == NULL)
			retval = fsroot_create_file_buffer(fs, file, &error);
		pthread_rwlock_unlock(&file->rwlock);

		if (retval == -1) {
			retval = E_SYSCALL;
			goto end;
		} else if (retval == 0 && file->buf == NULL) {
			error = E_EOF;
			goto end;
		}
	}

	pthread_rwlock_rdlock(&file->rwlock);
	for (idx = offset; idx < size && idx < file->buf_len; idx++)
		*(buf++) = file->buf[idx];
	pthread_rwlock_unlock(&file->rwlock);

	retval = idx;
	if (idx < size)
		error = E_EOF;

end:
	if (error_out && error != 0)
		*error_out = error;

	return retval;
}

/**
 * \param[in] fd a valid file descriptor, obtained by a previous call to fsroot_create() or fsroot_open()
 * \param[in] buf pointer to a buffer to take data from
 * \param[in] size length of the buffer
 * \param[in] offset offset to start writing from
 * \param[out] error_out pointer to an integer where the value `errno` will be placed, on error
 * \return the number of bytes written, or a negative error code on error
 *
 * This function will write \p size bytes from \p buf to the file referred to by \p fd, starting
 * at offset \p offset. If the end of the file is reached, the file is resized until, at least,
 * the remaining bytes can be written.
 *
 * This function returns the number of bytes written from \p buf to the file.
 *
 * If the file was not open for writing (neither `O_WRONLY` or `O_RDWR` were passed) then `FSROOT_E_SYSCALL`
 * is returned and \p error_out will be set to `EBADF`. If an error happens in some of the underlying OS services,
 * `FSROOT_E_SYSCALL` is returned and \p error_out is set to the value of `errno`.
 *
 * If an error happens, the file will not be modified in any way.
 */
int fsroot_write(fsroot_t *fs, int fd, const char *buf, size_t size, off_t offset, int *error_out)
{
	int retval = S_OK, error;
	unsigned int idx;
	struct fsroot_file *file;
	struct fsroot_file_descriptor *fildes;

	if (!fs || !buf || !size || fd < 0)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	pthread_rwlock_rdlock(&fs->open_files.rwlock);

	if (fd >= fs->open_files.num_files) {
		pthread_rwlock_unlock(&fs->open_files.rwlock);
		return E_BADARGS;
	}

	/*
	 * TODO maybe we should add additional sanity checks here,
	 * like checking the PID of the reader.
	 */
	fildes = fs->open_files.file_descriptors[fd];
	pthread_rwlock_unlock(&fs->open_files.rwlock);

	if (!fildes->can_write) {
		/* ERROR: this file was not opened for writing */
		retval = E_SYSCALL;
		error = EBADF;
		goto end_nolock;
	}
	file = fildes->file;

	pthread_rwlock_wrlock(&file->rwlock);

	if (file->buf == NULL) {
		retval = fsroot_create_file_buffer(fs, file, &error);

		if (retval == -1) {
			retval = E_SYSCALL;
			goto end;
		}
		retval = S_OK;
	}

	if (offset + size >= file->buf_len) {
		/*
		 * Attempting to write past the end of file,
		 * so resize the buffer. Beware file->buf might be NULL here.
		 * If we pass a NULL pointer to mm_realloc() it should just behave like
		 * malloc(). But this is not guaranteed for older implementations, and it is
		 * cheap to guard against this, so let's do it.
		 */
		if (file->buf_len == 0) {
			file->buf_len = offset + size;
		} else {
			while (offset + size >= file->buf_len)
				file->buf_len <<= 1;
		}

		file->buf = (file->buf ?
				mm_realloc(file->buf, file->buf_len) :
				mm_malloc0(file->buf_len));
	}

	for (idx = offset; idx < size + offset; idx++)
		file->buf[idx] = *(buf++);

	file->flags.is_synced = 0;
	if (file->flags.sync)
		retval = fsroot_sync_file(fs, file);

end:
	pthread_rwlock_unlock(&file->rwlock);
end_nolock:
	if (retval == S_OK)
		retval = idx;
	else if (retval == E_SYSCALL && error_out)
		*error_out = error;
	return retval;
}

/**
 * \param[in] path Relative path to a file
 * \returns `FSROOT_OK` on success, or a negative integer on error
 *
 * Makes sure the file specified by path has been fully written to the
 * underlying hardware media.
 *
 * If the specified file does not exists, or is not a regular file,
 * then this function returns `FSROOT_E_NOTEXISTS`.
 */
int fsroot_sync(fsroot_t *fs, const char *path)
{
	struct fsroot_file *file;

	if (!fs || !path)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	file = hash_table_get(fs->files, path);
	if (!file || !S_ISREG(file->mode))
		return E_NOTEXISTS;

	return fsroot_sync_file(fs, file);
}

/**
 * \param[in] path Relative path to a file
 * \return `FSROOT_OK` on success, or a negative integer on error
 *
 * This function will destroy all the open file descriptors for the file
 * specified by the path \p path. All the file descriptors for this file
 * (obtained with fsroot_create() and fsroot_open()) will no longer be valid,
 * and **calling fsroot_read() and fsroot_write() with either of these will have
 * undefined effects**.
 *
 * This function will sync the file to the underlying hardware media. If the file was marked
 * as temporary (`O_TMPFILE` was passed to fsroot_create() or fsroot_open()), or fsroot_delete()
 * was called on it and could not be removed because another process held a file descriptor for it,
 * then the file is removed from disk.
 *
 * If the specified file does not exist this function returns `FSROOT_E_NOTEXISTS`.
 * If the file exists but there are no file descriptors associated with it this function
 * returns `FSROOT_E_NOTOPEN`.
 */
int fsroot_release(fsroot_t *fs, const char *path)
{
	int retval;
	char fullpath[PATH_MAX];
	struct fsroot_file *file;

	if (!fs || !path)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	file = hash_table_get(fs->files, path);
	if (!file || !S_ISREG(file->mode))
		return E_NOTEXISTS;

	if (!file->flags.is_synced)
		fsroot_sync_file(fs, file);

	retval = __fsroot_release(fs, file, 1);

	/* Finally delete the file from disk if it has to be deleted */
	if (file->flags.tmpfile || file->flags.delete) {
		if (fsroot_fullpath(fs->root_path, path, fullpath, sizeof(fullpath))) {
			log_d(fs->logger, "fullpath: %s\n", fullpath);
			if (unlink(fullpath) == 0) {
				hash_table_remove(fs->files, path);
				mm_free(file->path);
				mm_free(file);
			} else {
				retval = E_SYSCALL;
			}
		} else {
			retval = E_BADARGS;
		}
	}

	return retval;
}

/*
 * \param[in] path Relative path to an existing file
 * \return `FSROOT_OK` on success, or a negative integer on error
 *
 * Deletes a file from disk.
 *
 * The specified file must be a regular file. If a non-regular file is specified,
 * or no such file exists, then this function returns `FSROOT_E_NOTEXISTS`.
 *
 * Other functions are provided to delete non-regular files. Use fsroot_symlink_delete()
 * to delete a symbolic link, and fsroot_rmdir() to delete a directory.
 *
 * If the specified file is open (another process holds a file descriptor for it) fsroot_delete()
 * will return `FSROOT_OK`, but the file will not be deleted at the moment. It will be deleted when
 * the last open file descriptor for the file is closed.
 *
 * If the underlying call to `unlink(2)` fails, `FSROOT_E_SYSCALL` is returned.
 */
int fsroot_delete(fsroot_t *fs, const char *path)
{
	int retval = S_OK, is_open = 0;
	struct fsroot_file *file;

	if (!fs || !path)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	file = hash_table_get(fs->files, path);
	if (!file)
		return E_NOTEXISTS;

	/*
	 * This is only for regular files.
	 * Any attempt to delete a non-regular file
	 * will be rejected.
	 */
	if (!S_ISREG(file->mode))
		return E_NOTEXISTS;

	/*
	 * Walk over all the open file descriptors to see
	 * if the file is open.
	 */
	pthread_rwlock_rdlock(&fs->open_files.rwlock);
	for (size_t i = 0; i < fs->open_files.num_files; i++) {
		if (fs->open_files.file_descriptors[i]->file == file) {
			is_open = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&fs->open_files.rwlock);

	if (is_open) {
		/*
		 * Someone keeps the file open, so we cannot remove it.
		 * We just mark it as "to be deleted".
		 */
		file->flags.delete = 1;
	} else {
		/* Compute the full path and delete the file on disk */
		if (unlink(file->path) == 0) {
			hash_table_remove(fs->files, path);
			mm_free(file->path);
			mm_free(file);
		} else {
			retval = E_SYSCALL;
		}
	}

	return retval;
}

/**
 * \param[in] path Relative path to a file
 * \param[out] out_st Pointer to a **stat(2)** structure
 * \return `FSROOT_OK` on success or a negative integer on error
 *
 * Retrieves the attributes of the file pointed by \p path, and places them
 * in the structure pointed to by \p out_st.
 *
 * These attributes are returned in a **stat(2)** structure just like the Unix
 * **stat(2)** system call does for any file outside fsroot. However, the attributes
 * returned by this function match those of fsroot's internal representation of the file.
 *
 * This function fills the **stat(2)** structure provided by the caller. It is an error
 * not to provide a pointer to a `struct stat`, and `FSROOT_E_BADARGS` is returned
 * if that is the case.
 *
 * If the file or directory pointed to by \p path does not exist, this function
 * returns `FSROOT_E_NOTEXISTS`.
 *
 * In any case, this function is guaranteed no to change the contents pointed to by \p out_st
 * in any way if a value different than `FSROOT_OK` is returned.
 */
int fsroot_getattr(fsroot_t *fs, const char *path, struct stat *out_st)
{
	struct fsroot_file *file;

	if (!fs || !path || !out_st)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	file = hash_table_get(fs->files, path);
	if (!file)
		return E_NOTEXISTS;

	if (lstat(file->path, out_st) == -1)
		return E_SYSCALL;

	out_st->st_mode = file->mode;
	out_st->st_uid = file->uid;
	out_st->st_gid = file->gid;

	return S_OK;
}

/**
 * \param[in] linkpath Relative path to the link
 * \param[in] target Relative path to the link target (file the link will point to)
 * \param[in] uid UID for the symbolic link
 * \param[in] gid GID for the symbolic link
 * \param[in] mode Mode for the symbolic link
 * \return `FSROOT_OK` on success or a negative value on error
 *
 * Creates a symbolic link.
 *
 * Parameter \p mode is basically there to specify the permission bits of the symlink.
 * This function will check whether \p mode effectively describes a symlink (with `S_ISLNK(mode)`)
 * and will fail returning `FSROOT_E_BADARGS` otherwise.
 *
 * If successful, a symlink will be created pointing to the file \p target (regardless of whether
 * it exists or not) with the specified UID, GID and permissions.
 *
 * This function relies on the `symlink(2)` libc function to create the symlink. If the call to `symlink(2)`
 * fails, `FSROOT_E_SYSCALL` is returned.
 *
 * If \p linkpath already exists, regardless of whether it is a symbolic link or not,
 * this function goes no further and returns `FSROOT_E_EXISTS`.
 */
int fsroot_symlink(fsroot_t *fs, const char *linkpath, const char *target, uid_t uid, gid_t gid, mode_t mode)
{
	struct fsroot_file *file = NULL;

	if (!fs || !linkpath || !target)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;
	if (!S_ISLNK(mode)) /* This is not a symlink! */
		return E_BADARGS;

	if (hash_table_contains(fs->files, linkpath))
		return E_EXISTS;

	file = fsroot_create_file(fs, linkpath, uid, gid, mode);
	if (!file)
		return E_BADARGS;

	if (strlen(target) >= LONG_MAX)
		return E_NOMEM;
	if (symlink(target, file->path) == -1)
		return E_SYSCALL;

	/* At this point symlink was created successfully, so we register it in our hash table */
	hash_table_put(fs->files, strdup(linkpath), file);

	return S_OK;
}

/*
 * \param[in] linkpath Relative path to the symbolic link
 * \return `FSROOT_OK` on success or a negative value on error
 * Deletes a symbolic link.
 *
 * If the specified file does not exist, or is not a symbolic link,
 * `FSROOT_E_NOTEXISTS` is returned.
 *
 * If the underlying call to `unlink(2)` fails, `FSROOT_E_SYSCALL`
 * is returned.
 */
int fsroot_symlink_delete(fsroot_t *fs, const char *linkpath)
{
	struct fsroot_file *file;

	if (!fs || !linkpath)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	file = hash_table_get(fs->files, linkpath);
	if (!file || !S_ISLNK(file->mode))
		return E_NOTEXISTS;

	if (unlink(file->path) == -1)
		return E_SYSCALL;

	hash_table_remove(fs->files, linkpath);
	mm_free(file->path);
	mm_free(file);

	return S_OK;
}

/**
 * \param[in] linkpath Relative path to a symbolic link
 * \param[in] dst Caller-supplied pointer to a buffer
 * \param[in] dstlen Pointer to an integer with the size of the buffer pointed to by \p dst
 * \return `FSROOT_OK` on success or a negative value on error
 *
 * Reads the target of a symbolic link (the path of the file it points to) and stores it
 * in \p buf. Unlike `lstat(2)`, fsroot_readlink() does append a NULL terminator at the end.
 *
 * If \p buf does not have enough space to store the target of the symbolic link
 * and a NULL terminator (as specified by \p *dstlen) this function stores in
 * the integer pointed to by \p dstlen the minimum length required to store the target path
 * and a NULL terminator, and then returns `FSROOT_E_NOMEM`.
 *
 * If \p linkpath does not exist or it is not a symbolic link, the function
 * returns `FSROOT_E_NOTEXISTS` without touching \p dst or \p dstlen.
 */
int fsroot_readlink(fsroot_t *fs, const char *linkpath, char *dst, size_t *dstlen)
{
	struct stat st;
	size_t required_size, actual_len;
	struct fsroot_file *file;

	if (!fs || !linkpath || !dst || !dstlen)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	file = hash_table_get(fs->files, linkpath);
	if (file == NULL || !S_ISLNK(file->mode))
		return E_NOTEXISTS;

	if (lstat(file->path, &st) == -1)
		return E_SYSCALL;
	if (st.st_size >= LONG_MAX)
		return E_NOMEM;

	required_size = st.st_size + 1;
	if (*dstlen < required_size) {
		*dstlen = required_size;
		return E_NOMEM;
	}

	actual_len = readlink(file->path, dst, *dstlen);
	if (actual_len == -1)
		return E_SYSCALL;

	dst[actual_len] = 0;
	return S_OK;
}

/**
 * \param[in] path Relative path, name of the directory to be created
 * \param[in] uid UID of the owner
 * \param[in] gid GID of the owner
 * \param[in] mode Mode bits (`mode_t`)
 * \return `FSROOT_OK` on success or a negative integer on error
 *
 * Creates a new directory. The new directory will have the specified
 * UID, GID and mode.
 *
 * The \p mode should be used primarily for setting the permissions.
 * Passing a \p mode that does not represent a directory (`S_ISDIR(mode)` is false)
 * is an error, and will cause `FSROOT_E_BADARGS` to be returned, without going further.
 *
 * If the specified directory exists, `FSROOT_E_EXISTS` is returned and no action is taken.
 * The existing directory is not modified in any way.
 *
 * If the underlying call to **mkdir(2)** fails, `FSROOT_E_SYSCALL` is returned.
 */
int fsroot_mkdir(fsroot_t *fs, const char *path, uid_t uid, gid_t gid, mode_t mode)
{
	struct fsroot_file *file;

	if (!fs || !path)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;
	if (!S_ISDIR(mode)) /* This is not a directory! */
		return E_BADARGS;

	if (hash_table_contains(fs->files, path))
		return E_EXISTS;

	file = fsroot_create_file(fs, path, uid, gid, mode);
	if (!file)
		return E_BADARGS;
	if (mkdir(file->path, S_IFDIR | 0700) == -1)
		goto error;

	hash_table_put(fs->files, strdup(path), file);

	return S_OK;
error:
	mm_free(file->path);
	mm_free(file);
	return E_SYSCALL;
}

/**
 * \param[in] path Relative path, name of the directory to be deleted
 * \return `FSROOT_OK` on success, or a negative integer on error
 *
 * Deletes a directory. The directory must be empty.
 *
 * If the specified path does not refer to a directory, or does not exist,
 * `FSROOT_E_NOTEXISTS` is returned.
 *
 * If the underlying call to **mkdir(2)** fails, `FSROOT_E_SYSCALL` is returned.
 * In particular, such a call will fail if the directory is not empty.
 */
int fsroot_rmdir(fsroot_t *fs, const char *path)
{
	int retval = S_OK;
	struct fsroot_file *file;

	if (!fs || !path)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;
	/* Obviously we loudly complain if someone tries to remove the root dir */
	if (path[0] == '/' && path[1] == 0)
		return E_BADARGS;

	file = hash_table_get(fs->files, path);
	if (file == NULL || !S_ISDIR(file->mode))
		return E_NOTEXISTS;

	if (rmdir(file->path) == -1)
		retval = E_SYSCALL;

	if (retval == S_OK) {
		hash_table_remove(fs->files, path);
		mm_free(file->path);
		mm_free(file);
	}

	return retval;
}

/**
 * \param[in] path Path for the file to be renamed
 * \param[in] newpath Path for the new name
 * \return `FSROOT_OK` on success or a negative integer on error
 *
 * Renames a file, symlink or directory. The contents of the file are not changed.
 * In the case of a directory, all its files and sub-directories are retained.
 *
 * If the file pointed to by \p path does not exist, `FSROOT_E_NOTEXISTS` is returned.
 *
 * In contrast, if a file already exists named \p newpath, `FSROOT_E_EXISTS` is returned
 * and no action is taken.
 */
int fsroot_rename(fsroot_t *fs, const char *path, const char *newpath)
{
	struct fsroot_file *file;
	char full_newpath[PATH_MAX];

	if (!fs || !path || !newpath || !fsroot_fullpath(fs->root_path, newpath, full_newpath, sizeof(full_newpath)))
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	log_d(fs->logger, "fullpath: %s\n", full_newpath);

	file = hash_table_get(fs->files, path);
	if (!file)
		return E_NOTEXISTS;

	if (hash_table_contains(fs->files, newpath))
		return E_EXISTS;

	if (rename(file->path, full_newpath) == -1)
		return E_SYSCALL;

	/* TODO maybe these should should be performed atomically */
	hash_table_remove(fs->files, path);

	file->path = mm_realloc((void *) file->path, strlen(full_newpath) + 1);
	strcpy((char *) file->path, full_newpath);
	hash_table_put(fs->files, strdup(newpath), file);

	return S_OK;
}

/**
 * \param[in] path Path to an existing file
 * \param[in] mode New mode for the file
 * \return `FSROOT_OK` on success or a negative integer on error
 *
 * Change the permissions of a file.
 *
 * Although the Unix **chmod(2)** changes the **mode** of the file,
 * this function only changes the permission bits. Parameter \p mode
 * must be full Unix mode, which specifies the type of file, as well as
 * the permissions (eg. 0100700). However, this function will reject attempts to change
 * the type of the file (eg. from regular file to directory), and will return
 * `FSROOT_E_BADARGS` if any such attempt is made.
 *
 * If the file \p path does not exist, `FSROOT_E_NOTEXISTS` is returned.
 */
int fsroot_chmod(fsroot_t *fs, const char *path, mode_t mode)
{
	struct fsroot_file *file;
	mode_t filetype = mode & S_IFMT;

	if (!fs || !path || !filetype)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	file = hash_table_get(fs->files, path);
	if (!file)
		return E_NOTEXISTS;

	/*
	 * Check that the user is not trying to change file type
	 * eg. directory to regular file
	 */
	if (filetype && ((file->mode & S_IFMT) != filetype))
		return E_BADARGS;

	file->mode = mode;
	return S_OK;
}

/**
 * \param[in] path Path to an existing file
 * \param[in] uid New UID for the file
 * \param[in] gid New GID for the file
 * \return `FSROOT_OK` on success or a negative integer on error
 *
 * Change the owner of a file.
 *
 * If the file \p path does not exist, `FSROOT_E_NOTEXISTS` is returned.
 */
int fsroot_chown(fsroot_t *fs, const char *path, uid_t uid, gid_t gid)
{
	struct fsroot_file *file;

	if (!fs || !path)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	file = hash_table_get(fs->files, path);
	if (!file)
		return E_NOTEXISTS;

	file->uid = uid;
	file->gid = gid;
	return S_OK;
}

struct fsroot_opendir_handle {
	fsroot_t *fs;
	DIR *dp;
	char *last_dir;
	char *prefix;
};

/*
 * We return a 'fsroot_file' to the user rather than a 'fsroot_directory', because
 * we do not want them to tinker with the directory's fields, such as num_entries.
 */
int fsroot_opendir(fsroot_t *fs, const char *path, void **outdir, int *error)
{
	struct fsroot_opendir_handle *h;
	struct fsroot_file *dir;
	char fullpath[PATH_MAX];
	int retval;
	DIR *dp;

	if (!fs || !path || !outdir || !fsroot_fullpath(fs->root_path, path, fullpath, sizeof(fullpath)))
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	log_d(fs->logger, "fullpath: %s\n", fullpath);

	dp = opendir(fullpath);
	if (!dp)
		return E_SYSCALL;

	dir = hash_table_get(fs->files, path);
	if (dir && S_ISDIR(dir->mode)) {
		h = mm_new0(struct fsroot_opendir_handle);
		h->fs = fs;
		h->dp = dp;
		h->prefix = strdup(path);
		*outdir = h;
		retval = S_OK;
	} else {
		retval = E_NOTEXISTS;
	}

	return retval;
}

int fsroot_readdir(void *dir, char *out, size_t outlen, int *err)
{
	struct fsroot_opendir_handle *h = dir;
	int initial_errno = errno;
	struct dirent *de;
	const char *source;
	char path[PATH_MAX];

	if (!h || !h->dp || !h->fs || !out || !outlen)
		return E_BADARGS;

	if (h->last_dir) {
		source = h->last_dir;
		goto return_dir;
	}

	for (;;) {
		de = readdir(h->dp);
		if (!de)
			goto error;

		if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
			continue;

		if (strcmp(h->prefix, "/"))
			snprintf(path, sizeof(path), "%s/%s", h->prefix, de->d_name);
		else
			snprintf(path, sizeof(path), "/%s", de->d_name);

		if (hash_table_contains(h->fs->files, path)) {
			log_d(h->fs->logger, "fsroot_readdir: Found path '%s'\n", path);
			// fprintf(stderr, "fsroot_readdir: Found path '%s'\n", path);
			break;
		} else {
			log_d(h->fs->logger, "fsroot_readdir: Path '%s' not in hash table\n", path);
			// fprintf(stderr, "fsroot_readdir: Path '%s' not in hash table\n", path);
		}
	}

	source = de->d_name;

return_dir:
	/* We test for the NULL-terminator as well */
	if (strlen(source) >= outlen) {
		if (!h->last_dir)
			h->last_dir = strdup(de->d_name);
		return E_NOMEM;
	}

	strncpy(out, source, outlen);
	if (h->last_dir)
		mm_free(h->last_dir);
	return S_OK;

error:
	/*
	 * If errno changed when we called readdir(),
	 * that means an error happened, actually.
	 * Else it just means there are no more files in the directory.
	 */
	if (initial_errno == errno) {
		return S_NOMORE;
	} else {
		if (err)
			*err = errno;
		return E_SYSCALL;
	}
}

void fsroot_closedir(void **dir)
{
	struct fsroot_opendir_handle *h = *dir;

	if (h) {
		closedir(h->dp);
		if (h->last_dir)
			mm_free(h->last_dir);
		if (h->prefix)
			mm_free(h->prefix);
		mm_free(h);
		*dir = NULL;
	}
}

static void __fsroot_deinit(fsroot_t *fs)
{
	hash_table_iterator iter;

	pthread_rwlock_wrlock(&fs->open_files.rwlock);

	for (unsigned int i = 0; i < fs->open_files.num_files; i++)
		mm_free(fs->open_files.file_descriptors[i]);

	mm_free(fs->open_files.file_descriptors);
	fs->open_files.num_slots = 0;
	fs->open_files.num_files = 0;

	if (fs->files) {
		hash_table_lock(fs->files);
		for (hash_table_iterate(fs->files, &iter); hash_table_iter_next(&iter);) {
			__fsroot_release(fs, iter.value, 0);
	//		hash_table_remove(fs->files, iter.key);
			if (((struct fsroot_file *) iter.value)->path)
				mm_free(((struct fsroot_file *) iter.value)->path);
			mm_free(iter.value);
		}
		hash_table_unlock(fs->files);

		hash_table_destroy(fs->files);
	}

	pthread_rwlock_unlock(&fs->open_files.rwlock);
	pthread_rwlock_destroy(&fs->open_files.rwlock);

	/* Unload configuration */
	if (fs->c)
		fs->c->deinit(&fs->c);
	fs->started = 0;
}

void fsroot_deinit(fsroot_t **fs)
{
	if (fs && *fs) {
		__fsroot_deinit(*fs);
		crypto_deinit(&(*fs)->fs_crypto);
		mm_free((*fs)->database_file);
		mm_free((*fs)->c);
		mm_free(*fs);
	}
}

/**
 * \param[in] filename Path to a file (absolute or relative)
 * \return `FSROOT_OK` on success, or an `FSROOT_E_*` negative value on error
 *
 * Save file metadata to disk.
 *
 * The metadata is basically a list of files attached to a `stat`-like
 * data structure that contains the file permissions and owner.
 *
 * If the specified file already exists, fsroot_persist() will try to delete it
 * before creating a new one. If it can't delete the file, `FSROOT_E_EXISTS` will be returned.
 *
 * The file metadata is kept in memory while FSRoot is running.
 *
 * Please note that calling fsroot_deinit() will cause all that metadata to be deleted and
 * will be lost unless fsroot_persist() has been called before.
 */
int fsroot_persist(fsroot_t *fs, const char *filename)
{
	int retval;
	fsroot_db_t *db;
	hash_table_iterator iter;

	if (!fs || !filename || !*filename)
		return E_BADARGS;
	if (!fs->started)
		return E_NOTSTARTED;

	retval = fsroot_db_create(filename);
	if (retval == E_EXISTS) {
		/*
		 * Database file already exists.
		 * Try to delete it and call fsroot_db_create() again.
		 */
		if (unlink(filename) == -1)
			return E_EXISTS;

		retval = fsroot_db_create(filename);
	}
	if (retval != S_OK)
		return retval;

	retval = fsroot_db_open(filename, &db);
	if (retval != S_OK)
		return retval;

	/* We lock the files exclusively while we dump them to the DB */
	pthread_rwlock_wrlock(&fs->open_files.rwlock);
	hash_table_lock(fs->files);
	for (hash_table_iterate(fs->files, &iter); hash_table_iter_next(&iter);) {
		const char *path = iter.key;
		struct fsroot_file *file = iter.value;

		/* Skip the root dir */
		if (strcmp(path, "/"))
			fsroot_db_add_file_entry(db, path, file);
	}
	hash_table_unlock(fs->files);
	pthread_rwlock_unlock(&fs->open_files.rwlock);

	return fsroot_db_close(&db);
}

/*
 * \param[in] filename An absolute path
 * \return `FSROOT_OK` if the database file path was successfully changed or a negative error code otherwise
 *
 * Sets the file where the filesystem information will be saved.
 *
 * An empty or NULL value for \p filename disables persistence at all.
 * This means that all the filesystem information will be lost after calling fsroot_deinit().
 *
 * The length of the \p filename argument must not be greater than `PATH_MAX`.
 */
int fsroot_set_database_file(fsroot_t *fs, const char *filename)
{
	if (!fs)
		return E_BADARGS;

	if (!filename || !*filename) {
		if (fs->database_file)
			mm_free(fs->database_file);
	} else {
		if (strlen(filename) > PATH_MAX)
			return E_NOMEM;
		fs->database_file = strdup(filename);
	}

	return S_OK;
}

/**
 * \param[in] root Root folder where fsroot will store its files internally
 * \return `FSROOT_OK` on success or a negative integer on error
 *
 * If \p dir is NULL or empty `FSROOT_E_BADARGS` is returned.
 *
 * The length of the string \p root should be no greater than `PATH_MAX`, or
 * `FSROOT_E_NOMEM` is returned.
 */
int fsroot_set_root_directory(fsroot_t *fs, const char *dir)
{
	size_t root_path_len = 0;

	if (!fs || !dir || !*dir)
		return E_BADARGS;

	root_path_len = strlen(dir);
	if (root_path_len > PATH_MAX)
		return E_NOMEM;

	strcpy(fs->root_path, dir);
	return S_OK;
}

int fsroot_set_config_file(fsroot_t *fs, const char *filename)
{
	char *algo;
	int retval = S_OK;

	fs->c = mm_new0(config_t);

	if (config_init(fs->c, filename) != CONFIG_OK) {
		mm_free(fs->c);
		return E_UNKNOWN;
	}

	algo = fs->c->get_crypto_algorithm(fs->c);
	if (algo) {
		retval = crypto_set_algorithm(fs->fs_crypto, algo);
		mm_free(algo);
	}

	return retval;
}

/**
 * \param[in] root Root folder where fsroot will store its files internally
 * \return `FSROOT_OK` on success or a negative integer on error
 *
 * Initialize the fsroot environment.
 *
 * The length of the string \p root should be no greater than `PATH_MAX`, or
 * `FSROOT_E_NOMEM` is returned.
 */
int fsroot_init(fsroot_t **fs, struct logger *l)
{
	fsroot_t *fsroot = NULL;

	if (!fs)
		return E_BADARGS;

	/* Initialize the fsroot handle */
	*fs = mm_new0(fsroot_t);
	fsroot = *fs;
	fsroot->logger = l;
	fsroot->files = NULL;
	memset(&fsroot->open_files, 0, sizeof(fsroot->open_files));

	/* TODO how do we balance the space? (eg. Android) */
	fsroot->files = make_string_hash_table(10);

	fsroot->open_files.num_files = 0;
	fsroot->open_files.num_slots = OPEN_FILES_INITIAL_NUM_SLOTS;
	fsroot->open_files.file_descriptors = mm_mallocn0(fsroot->open_files.num_slots,
			sizeof(struct fsroot_file_descriptor*));
	pthread_rwlock_init(&fsroot->open_files.rwlock, NULL);

	crypto_init(&(*fs)->fs_crypto);
	crypto_set_logger((*fs)->fs_crypto, l);

	return S_OK;
}

static int load_from_database(fsroot_t *fs, fsroot_db_t *db)
{
	int retval = E_UNKNOWN;
	fsroot_db_iter_t *it = NULL;
	char *filename = NULL;
	struct fsroot_file file, *pfile;

	retval = fsroot_db_iter_init(&it, db);
	if (retval != S_OK)
		return retval;

	do {
		retval = fsroot_db_iter_next(it, &filename, &file);

		if (retval == S_OK) {
			pfile = fsroot_create_file(fs,
					filename,
					file.uid,
					file.gid,
					file.mode);
			if (pfile)
				hash_table_put(fs->files, filename, pfile);
		}
	} while (retval == S_OK);

	fsroot_db_iter_deinit(&it);
	return (retval == S_NOMORE ?
		S_OK :
		retval);
}

int fsroot_start(fsroot_t *fs, uid_t root_uid, gid_t root_gid, mode_t root_mode)
{
	int retval = S_OK;
	struct stat st;
	struct fsroot_file *root_dir = NULL;
	fsroot_db_t *db = NULL;

	/* Initialize the root directory */
	if (!fs->root_path[0])
		return E_BADARGS;
	if (stat(fs->root_path, &st) == -1 || !S_ISDIR(st.st_mode))
		return E_NOT_DIRECTORY;

	if (!S_ISDIR(root_mode))
		return E_BADARGS;

	root_dir = mm_new0(struct fsroot_file);
	root_dir->path = strdup(fs->root_path);
	root_dir->uid = root_uid;
	root_dir->gid = root_gid;
	root_dir->mode = root_mode;
	hash_table_put(fs->files, "/", root_dir);

	/*
	 * Initialize the filesystem from the database.
	 * If no database was provided then it will be empty (no files, other
	 * than the root directory).
	 */
	if (fs->database_file) {
		if ((retval = fsroot_db_create(fs->database_file)) == E_EXISTS) {
			if (fsroot_db_open(fs->database_file, &db) == S_OK) {
				load_from_database(fs, db);
				fsroot_db_close(&db);
				retval = S_OK;
			} else {
				retval = E_NODB;
			}
		}
	}

	if (retval == S_OK)
		fs->started = 1;
	return retval;
}

/** @} */
