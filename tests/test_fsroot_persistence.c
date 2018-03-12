#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include "../linux/fsroot.h"
#include "../linux/fsroot-db.h"
#include "../mm.h"

#define DB_FILE "mydb.db"
char dir[] = "fsroot-root";

static void check_sqlite_entries(const char *db_filename, size_t n_args, ...)
{
	va_list args;
	int match_found = 0;
	size_t i_arg;
	const char *filename_expected;
	const unsigned char *filename;
	struct fsroot_file *file;
	mode_t mode;
	uid_t uid;
	gid_t gid;
	char sql[] = "SELECT file_name, perms, uid, gid FROM fsroot_files";
	sqlite3 *db;
	sqlite3_stmt *stmt;

	va_start(args, n_args);

	for (i_arg = 0; i_arg < n_args && !match_found; i_arg += 2) {
		filename_expected = va_arg(args, const char *);
		file = va_arg(args, struct fsroot_file *);

		ck_assert_int_eq(sqlite3_open(db_filename, &db), SQLITE_OK);
		ck_assert_int_eq(sqlite3_prepare_v2(
				db,
				sql, sizeof(sql),
				&stmt, NULL), SQLITE_OK);

		while (sqlite3_step(stmt) == SQLITE_ROW) {
			filename = sqlite3_column_text(stmt, 0);
			mode = sqlite3_column_int(stmt, 1);
			uid = sqlite3_column_int(stmt, 2);
			gid = sqlite3_column_int(stmt, 3);

			if (strcmp(filename_expected, (const char *) filename) == 0 &&
			    mode == file->mode &&
			    uid == file->uid &&
			    gid == file->gid) {
				match_found = 1;
				break;
			}
		}

		sqlite3_finalize(stmt);
		sqlite3_close(db);

		if (!match_found) {
			ck_abort_msg("No row found for: [filename = %s, mode = %o, UID = %d, GID = %d]",
				     filename_expected, file->mode, file->uid, file->gid);
		}
	}

	va_end(args);
}

/*
 * This test checks that calling fsroot_db_open() on a
 * non-existing file will make that function fail.
 */
START_TEST(test_persist_non_existing_file)
{
	int retval;
	fsroot_db_t *db;

	/* Delete database file if it exists, for some reason */
	if (access(DB_FILE, F_OK) == 0)
		unlink(DB_FILE);

	retval = fsroot_db_open(DB_FILE, &db);
	ck_assert_msg(retval == E_NOTEXISTS, "fsroot_db_open('%s') returned %d (should return %d)",
		      DB_FILE,
		      retval,
		      E_NOTEXISTS);
}
END_TEST

/*
 * This test checks that an existing file with a non-existing
 * SQLite schema will make fsroot_db_open() fail.
 */
START_TEST(test_persist_non_existing_schema)
{
	fsroot_db_t *db;
	int retval, fd = creat(DB_FILE, 0600);
	ck_assert(fd != -1);
	close(fd);

	retval = fsroot_db_open(DB_FILE, &db);
	ck_assert_msg(retval == E_NOTINITIALIZED, "fsroot_db_open('%s') returned %d (should return %d)",
		      DB_FILE,
		      retval,
		      E_NOTINITIALIZED);
}
END_TEST

/*
 * This test checks that an existing file which is not both readable and writable
 * will make fsroot_db_open() fail with FSROOT_E_NOTEXISTS.
 */
START_TEST(test_persist_wrong_attrs)
{
	fsroot_db_t *db;
	/* Create a new file with read-only permissions */
	int retval, fd = creat(DB_FILE, 0400);
	ck_assert(fd != -1);
	close(fd);

	retval = fsroot_db_open(DB_FILE, &db);
	ck_assert_msg(retval == E_NOTEXISTS, "fsroot_db_open('%s') returned %d (should return %d)",
		      DB_FILE,
		      retval,
		      E_NOTEXISTS);

	/* Change the permissions to write-only */
	ck_assert_msg(chmod(DB_FILE, 0200) != -1, "Could not chmod file '%s' to 0200", DB_FILE);

	retval = fsroot_db_open(DB_FILE, &db);
	ck_assert_msg(retval == E_NOTEXISTS, "fsroot_db_open('%s') returned %d (should return %d)",
		      DB_FILE,
		      retval,
		      E_NOTEXISTS);
}
END_TEST

/*
 * This test checks that adding an existing file again
 * with fsroot_db_add_file_entry() will update that entry's contents,
 * and return FSROOT_OK_EXISTS.
 */
START_TEST(test_persist_update_existing_file)
{
	int retval;
	fsroot_db_t *db;
	struct fsroot_file *file;

	retval = fsroot_db_create(DB_FILE);
	ck_assert_msg(retval == S_OK, "fsroot_db_create('%s') returned %d", DB_FILE, retval);

	retval = fsroot_db_open(DB_FILE, &db);
	ck_assert_msg(retval == S_OK, "fsroot_db_open('%s') returned %d", DB_FILE, retval);
	ck_assert(db != NULL);

	file = mm_new0(struct fsroot_file);
	file->mode = 0600;
	file->uid = 1000;
	file->gid = 1000;
	retval = fsroot_db_add_file_entry(db, "foo_file", file);
	ck_assert_msg(retval == S_OK, "fsroot_db_add_file_entry() returned %d (should return %d)",
		      retval, S_OK);

	file->mode = 0400;
	file->gid = 1001;
	retval = fsroot_db_add_file_entry(db, "foo_file", file);
	ck_assert_msg(retval == S_EXISTS, "fsroot_db_add_file_entry() returned %d "
		      "(should return FSROOT_OK_EXISTS (%d))", retval, S_EXISTS);

	ck_assert(fsroot_db_close(&db) == S_OK);
	mm_free(file);
}
END_TEST

/*
 * This test checks that the database file created by fsroot_db_create()
 * has mode 0600 and is owned by the process' effective UID and GID.
 */
START_TEST(test_persist_appropriate_attrs)
{
	struct stat st;
	uid_t uid = getuid();
	gid_t gid = getgid();

	/* Delete database file if it exists, for some reason */
	if (access(DB_FILE, F_OK) == 0)
		unlink(DB_FILE);

	ck_assert(fsroot_db_create(DB_FILE) == S_OK);

	ck_assert(stat(DB_FILE, &st) == 0);
	ck_assert_msg(st.st_uid == uid, "UID is %d (should be %d)", st.st_uid, uid);
	ck_assert_msg(st.st_gid == gid, "GID is %d (should be %d)", st.st_gid, gid);

	mode_t mode = st.st_mode & (~S_IFMT);
	ck_assert_msg(mode == 0600, "Mode is %o (should be 0600)", mode);
}
END_TEST

START_TEST(test_persist)
{
	int retval;
	fsroot_db_t *db;
	struct fsroot_file *file[2];

	/* Delete database file if it exists, for some reason */
	if (access(DB_FILE, F_OK) == 0)
		unlink(DB_FILE);

	/* Create a new database file */
	retval = fsroot_db_create(DB_FILE);
	ck_assert_msg(retval == S_OK, "fsroot_db_create('%s') returned %d", DB_FILE, retval);

	/* Open database file and insert some entries */
	retval = fsroot_db_open(DB_FILE, &db);
	ck_assert_msg(retval == S_OK, "fsroot_db_open('%s') returned %d", DB_FILE, retval);
	ck_assert(db != NULL);

	file[0] = mm_new0(struct fsroot_file);
	file[0]->mode = 0600;
	file[0]->uid = 1000;
	file[0]->gid = 1000;
	retval = fsroot_db_add_file_entry(db, "file_1", file[0]);
	ck_assert_msg(retval == S_OK, "fsroot_db_add_file_entry() returned %d", retval);

	file[1] = mm_new0(struct fsroot_file);
	file[1]->mode = 0777;
	file[1]->uid = 2000;
	file[1]->gid = 2000;
	retval = fsroot_db_add_file_entry(db, "file_2", file[1]);
	ck_assert_msg(retval == S_OK, "fsroot_db_add_file_entry() returned %d", retval);

	ck_assert(fsroot_db_close(&db) == S_OK);

	/* Check entries */
	check_sqlite_entries(DB_FILE, 4, "file_1", file[0], "file_2", file[1]);

	mm_free(file[1]);
	mm_free(file[0]);
}
END_TEST

START_TEST(test_fsroot_persist)
{
	fsroot_t *fs;
	int retval, err, fd[2];
	struct fsroot_file *file[2];

	/* Create FSRoot root directory */
	ck_assert(mkdir(dir, 0744) != -1);

	/* Initialize FSRoot */
	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init() returned %d\n", retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	/* Create the database file */
	retval = fsroot_db_create(DB_FILE);
	ck_assert_msg(retval == S_OK, "fsroot_db_create('%s') returned %d", DB_FILE, retval);

	/* Create some files in FSRoot */
	fd[0] = fsroot_create(fs, "file_0", 1000, 1000, 0100700, O_CREAT | O_RDWR, &err);
	ck_assert_msg(fd[0] >= 0, "fsroot_create('file_0') returned %d (err: %d)\n",
		      fd[0], err);
	fd[1] = fsroot_create(fs, "file_1", 1000, 1000, 0100700, O_RDWR, &err);
	ck_assert_msg(fd[1] >= 0, "fsroot_create('file_1') returned %d (err: %d)\n",
		      fd[1], err);

	retval = fsroot_release(fs, "file_0");
	ck_assert_msg(retval == S_OK, "fsroot_release('file_0') returned %d", retval);
	retval = fsroot_release(fs, "file_1");
	ck_assert_msg(retval == S_OK, "fsroot_release('file_1') returned %d", retval);

	/* Persist files to database */
	retval = fsroot_persist(fs, DB_FILE);
	ck_assert_msg(retval == S_OK, "fsroot_persist('%s') returned %d", DB_FILE, retval);

	fsroot_deinit(&fs);

	/* Check entries in database */
	file[0] = mm_new0(struct fsroot_file);
	file[0]->mode = 0100700;
	file[0]->uid = 1000;
	file[0]->gid = 1000;

	file[1] = mm_new0(struct fsroot_file);
	file[1]->mode = 0100700;
	file[1]->uid = 1000;
	file[1]->gid = 1000;

	check_sqlite_entries(DB_FILE, 4, "file_0", file[0], "file_1", file[1]);

	mm_free(file[1]);
	mm_free(file[0]);
}
END_TEST

void teardown()
{
	/* Delete DIR recursively */
	DIR *d;
	struct dirent *de = NULL;
	char path[PATH_MAX];

	d = opendir(dir);
	if (d) {
		do {
			de = readdir(d);
			if (de && strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
				snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
				unlink(path);
			}
		} while (de);

		closedir(d);
		rmdir(dir);
	}

	/* Delete DB_FILE */
	struct stat st;
	if (stat(DB_FILE, &st) != -1) {
		ck_assert_msg(unlink(DB_FILE) == 0,
			      "Could not unlink file '%s'",
			      DB_FILE);
	}
}

Suite *fsroot_suite()
{
	Suite *s;
	TCase *tc;

	s = suite_create("fsroot persistence tests");

	tc = tcase_create("core");
	tcase_add_test(tc, test_persist_non_existing_file);
	tcase_add_test(tc, test_persist_non_existing_schema);
	tcase_add_test(tc, test_persist_wrong_attrs);
	tcase_add_test(tc, test_persist_update_existing_file);
	tcase_add_test(tc, test_persist_appropriate_attrs);
	tcase_add_test(tc, test_persist);
	tcase_add_test(tc, test_fsroot_persist);
	tcase_add_checked_fixture(tc, NULL, teardown);

	suite_add_tcase(s, tc);
	return s;
}

int main()
{
	int n_failed_tests;
	Suite *s;
	SRunner *sr;

	s = fsroot_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	n_failed_tests = srunner_ntests_failed(sr);
	srunner_free(sr);

	return n_failed_tests == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

