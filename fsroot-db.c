/*
 * fsroot-db.c
 *
 *  Created on: 28 Jul 2017
 *      Author: Ander Juaristi
 */
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sqlite3.h>
#include "mm.h"
#include "fsroot-db.h"
#include "fsroot-return-codes.h"

/**
 * \file
 * \brief fsroot database management functions
 * \defgroup fsroot-db fsroot persistence layer
 *
 * @{
 */

struct fsroot_db_st
{
	sqlite3 *sqlite;
};

struct fsroot_db_iter_st
{
	sqlite3_stmt *sqlite_stmt;
};

static int create_schema(sqlite3 *sqlite)
{
	char sql[] = "CREATE TABLE fsroot_files ("
		"file_name TEXT PRIMARY KEY,"
		"perms INT,"
		"uid INT,"
		"gid INT)";
	sqlite3_stmt *sqlite_stmt;

	/* Create a prepared statement ... */
	int retval = sqlite3_prepare_v2(
		sqlite,
		sql,
		sizeof(sql),  // As per the docs, there's a small performance advantage on this
		&sqlite_stmt,
		NULL);
	if (retval != SQLITE_OK)
		return retval;
	if (!sqlite_stmt)
		return -1; // this should never happen

	/* ...and run it */
	retval = sqlite3_step(sqlite_stmt);
	sqlite3_finalize(sqlite_stmt);

	if (retval != SQLITE_DONE)
		return retval;

	return 0;
}

static int create_file_excl(const char *fname)
{
	int fd;

	if ((fd = open(fname, O_CREAT|O_EXCL, 0600)) == -1)
		return (errno == EEXIST ? FSROOT_E_EXISTS : FSROOT_E_SYSCALL);

	close(fd);
	return 0;
}

/**
 * \param[in] fname A file name (absolute or relative)
 * \return `FSROOT_OK` on success or one of the `FSROOT_E_*` error codes
 *
 * Create a database file on the specified path and initialize it.
 *
 * The file will be created with mode 0600 (`-rw-------`).
 *
 * The file must not exist. If it does, this function will return `FSROOT_E_EXISTS`.
 *
 * If for some reason the file cannot be created, `FSROOT_E_SYSCALL` will be returned.
 * Furthermore, if SQLite cannot load the schema in the database file, `FSROOT_E_UNKNOWN` will be returned.
 */
int fsroot_db_create(const char *fname)
{
	int retval = FSROOT_OK;
	sqlite3 *sqlite;

	if (!fname || !*fname)
		return FSROOT_E_BADARGS;

	if ((retval = create_file_excl(fname)) != 0)
		return retval;

	if (sqlite3_open(fname, &sqlite) != SQLITE_OK) {
		retval = FSROOT_E_SYSCALL;
		goto end;
	}

	if (create_schema(sqlite) != 0) {
		retval = FSROOT_E_UNKNOWN;
		goto end;
	}

end:
	if (retval != FSROOT_OK)
		unlink(fname);
	sqlite3_close(sqlite);
	return retval;
}

/**
 * \param[in] fname A file name (absolute or relative)
 * \param[in] db A double pointer to an `fsroot_db_t` database handle
 * \return `FSROOT_OK` on success or one of the `FSROOT_E_*` error codes
 *
 * Open the database stored in the provided file.
 *
 * The file must exist and must have already been initialized with the appropriate schema.
 * This is done with a previous call to fsroot_db_create().
 *
 * If the file does not exist, or is not both readable and writable
 * this function will fail and return `FSROOT_E_NOTEXISTS`.
 *
 * If the file has not been appropriately initialized this function will return `FSROOT_E_NOTINITIALIZED`.
 */
int fsroot_db_open(const char *fname, fsroot_db_t **db)
{
	int retval = FSROOT_E_UNKNOWN;
	struct fsroot_db_st *m_db = NULL;

	if (!fname || !*fname || !db)
		return FSROOT_E_BADARGS;

	/* Initialize handle to NULL */
	*db = NULL;
	m_db = mm_new0(struct fsroot_db_st);

	/*
	 * Open the SQLite database.
	 *
	 * This will also check that the file exists (with the SQLITE_OPEN_READWRITE flag).
	 * We also check that the database file is writable.
	 */
	retval = sqlite3_open_v2(fname, &m_db->sqlite, SQLITE_OPEN_READWRITE, NULL);
	if (retval != SQLITE_OK || access(fname, W_OK) == -1) {
		if (retval != SQLITE_OK)
			retval = (retval == SQLITE_CANTOPEN ? FSROOT_E_NOTEXISTS : FSROOT_E_SYSCALL);
		else
			retval = FSROOT_E_NOTEXISTS;
		goto close_and_error;
	}

	/* Check the schema is present */
	if (sqlite3_table_column_metadata(m_db->sqlite,
		NULL, // Database name - there's just one so we don't care
		"fsroot_files", "file_name", // Table and column
		NULL,
		NULL,
		NULL,
		NULL,
		NULL) == SQLITE_ERROR) {
		retval = FSROOT_E_NOTINITIALIZED;
		goto close_and_error;
	}
	if (sqlite3_table_column_metadata(m_db->sqlite,
		NULL, // Database name - there's just one so we don't care
		"fsroot_files", "perms", // Table and column
		NULL,
		NULL,
		NULL,
		NULL,
		NULL) == SQLITE_ERROR) {
		retval = FSROOT_E_NOTINITIALIZED;
		goto close_and_error;
	}

	/* Return handle to caller */
	*db = m_db;
	return FSROOT_OK;

close_and_error:
	sqlite3_close(m_db->sqlite);
	mm_free(m_db);
	return retval;
}

static int fsroot_db_prepare_statement(const char *sql, int sql_len, sqlite3 *db, sqlite3_stmt **stmt)
{
	int retval = sqlite3_prepare_v2(
		db,
		sql,
		sql_len,
		stmt,
		NULL);

	if (retval != SQLITE_OK)
		sqlite3_finalize(*stmt);
	else if (!*stmt)
		return FSROOT_E_UNKNOWN;

	return retval;
}

static int fsroot_db_insert_file(fsroot_db_t *db, const char *fname, struct fsroot_file *file)
{
	char sql[] = "INSERT INTO fsroot_files (file_name, perms, uid, gid) "
		"VALUES (?, ?, ?, ?)";
	int retval;
	sqlite3_stmt *stmt;

	retval = fsroot_db_prepare_statement(sql, sizeof(sql), db->sqlite, &stmt);
	if (retval != SQLITE_OK)
		return retval;

	/* Bind the params, execute and finalize the statement */
	sqlite3_bind_text(stmt, 1, fname, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, file->mode);
	sqlite3_bind_int(stmt, 3, file->uid);
	sqlite3_bind_int(stmt, 4, file->gid);

	retval = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return retval;
}

static int fsroot_db_update_file(fsroot_db_t *db, const char *fname, struct fsroot_file *file)
{
	char sql[] = "UPDATE fsroot_files SET perms = ?, uid = ?, gid = ? "
		"WHERE file_name = ?";
	int retval;
	sqlite3_stmt *stmt;

	retval = fsroot_db_prepare_statement(sql, sizeof(sql), db->sqlite, &stmt);
	if (retval != SQLITE_OK)
		return retval;

	/* Bind the params, execute and finalize the statement */
	sqlite3_bind_int(stmt, 1, file->mode);
	sqlite3_bind_int(stmt, 2, file->uid);
	sqlite3_bind_int(stmt, 3, file->gid);
	sqlite3_bind_text(stmt, 4, fname, -1, SQLITE_STATIC);

	retval = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	return retval;
}

/**
 * \param[in] db A pointer to an `fsroot_db_t` database handle, obtained with fsroot_db_open()
 * \param[in] fname Name of the file in the file entry
 * \param[in] mode Mode of the file (permissions + file type)
 * \return `FSROOT_OK` or `FSROOT_OK_EXISTS` on success, or one of the `FSROOT_E_*` error codes.
 *
 * Add a new file entry to the database.
 *
 * If the file already exists, its mode will be updated and `FSROOT_OK_EXISTS` will be returned.
 *
 * If for some reason the underlying SQLite fails this function will return `FSROOT_E_UNKNOWN`.
 */
int fsroot_db_add_file_entry(fsroot_db_t *db, const char *fname, struct fsroot_file *file)
{
	int retval, file_was_updated = 0;

	if (!db || !db->sqlite || !fname || !*fname || !file)
		return FSROOT_E_BADARGS;

	retval = fsroot_db_insert_file(db, fname, file);
	if (retval == SQLITE_CONSTRAINT) {
		/*
		 * We violated a primary key constraint.
		 * This means the file already exists, so let's try to update its contents.
		 */
		retval = fsroot_db_update_file(db, fname, file);
		file_was_updated = 1;
	}

	if (retval != SQLITE_DONE)
		return FSROOT_E_UNKNOWN;

	return file_was_updated ? FSROOT_OK_EXISTS : FSROOT_OK;

}

int fsroot_db_iter_init(fsroot_db_iter_t **it, fsroot_db_t *db)
{
	int retval;
	sqlite3_stmt *stmt = NULL;
	char sql[] = "SELECT * FROM fsroot_files";

	if (!db || !it || !db->sqlite)
		return FSROOT_E_BADARGS;

	retval = fsroot_db_prepare_statement(sql, sizeof(sql), db->sqlite, &stmt);
	if (retval != SQLITE_OK) {
		sqlite3_finalize(stmt);
		return retval;
	}

	*it = mm_new0(fsroot_db_iter_t);
	(*it)->sqlite_stmt = stmt;

	return FSROOT_OK;
}

/**
 * Either or both of \p fname or \p f might be NULL. If that is the case the iterator will be advanced
 * to the next item normally, but the current row's data will not be copied in the NULL parameters.
 *
 * The caller is responsible for freeing the memory at \p fname allocated by this function.
 *
 * This function might set either or both of \p pname or \p f to all zeros before
 * filling them with the right values.
 */
int fsroot_db_iter_next(fsroot_db_iter_t *it, char **fname, struct fsroot_file *f)
{
	int retval = FSROOT_E_UNKNOWN;
	const char *sqlite_filename;

	if (!it)
		return FSROOT_E_BADARGS;

	switch (sqlite3_step(it->sqlite_stmt)) {
	case SQLITE_ROW:
		/* We have a new row - pass it up to caller */
		if (fname) {
			sqlite_filename = (const char *) sqlite3_column_text(it->sqlite_stmt, 1);
			if (!sqlite_filename)
				return FSROOT_E_SYSCALL; /* this should not happen */
			*fname = strdup(sqlite_filename);
		}
		if (f) {
			f->mode = sqlite3_column_int(it->sqlite_stmt, 2);
			f->uid = sqlite3_column_int(it->sqlite_stmt, 3);
			f->gid = sqlite3_column_int(it->sqlite_stmt, 4);
		}
		retval = FSROOT_OK;
		break;
	case SQLITE_DONE:
		/* There are no more rows */
		retval = FSROOT_NOMORE;
		break;
	case SQLITE_BUSY:
		retval = FSROOT_E_AGAIN;
		break;
	default:
		retval = FSROOT_E_SYSCALL;
		break;
	}

	return retval;
}

void fsroot_db_iter_deinit(fsroot_db_iter_t **it)
{
	if (it && *it) {
		sqlite3_finalize((*it)->sqlite_stmt);
		*it = NULL;
	}
}

/**
 * \param[in] db A double pointer to an `fsroot_db_t` database handle
 * \return `FSROOT_OK` on success, or one of the `FSROOT_E_*` error codes.
 *
 * Close an open database handle.
 *
 * The provided database handle \p db and all its linked resources will be freed, and the supplied
 * pointer to \p db **will be set to NULL**. The database file will also be closed.
 *
 * If some other process is in the middle of a transaction with the same \p db handle,
 * this function will fail to close the database, and will return `FSROOT_E_BUSY`. This will
 * most of the time happen when fsroot_db_close() is called while at the same time fsroot_db_add_file_entry()
 * is running.
 *
 * If, for some other reason the underlying SQLite engine fails to close the database, this function
 * will return `FSROOT_E_UNKNOWN`.
 */
int fsroot_db_close(fsroot_db_t **db)
{
	if (!db || !*db || !(*db)->sqlite)
		return FSROOT_E_BADARGS;

	int retval = sqlite3_close((*db)->sqlite);
	if (retval == SQLITE_BUSY)
		return FSROOT_E_BUSY;
	else if (retval != SQLITE_OK)
		return FSROOT_E_UNKNOWN;

	mm_free(*db);
	return FSROOT_OK;
}

/** @} */
