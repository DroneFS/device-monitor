#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include "../linux/fsroot.h"

char dir[] = "fsroot-root";

struct expected_dir
{
	char *dirname;
	int checked;
};

void create_dir_tree(fsroot_t *fs)
{
	mode_t dirmode = 0040700;
	ck_assert_int_eq(fsroot_mkdir(fs, "dir", 1000, 1000, dirmode), S_OK);
	ck_assert_int_eq(fsroot_mkdir(fs, "dir/dir_1", 1000, 1000, dirmode), S_OK);
	ck_assert_int_eq(fsroot_mkdir(fs, "dir/dir_2", 1000, 1000, dirmode), S_OK);
}

static int check_dir(const char *dirname, struct expected_dir *dirs)
{
	struct expected_dir *dir;

	for (dir = dirs; dir->dirname; dir++) {
		if (strcmp(dir->dirname, dirname) == 0 &&
			dir->checked == 0) {
			/* Mark this directory as checked */
			dir->checked = 1;
			return 1;
		}
	}

	return 0;
}

START_TEST(test_fsroot_readdir)
{
	fsroot_t *fs;
	void *dh;
	int retval, err;
	char dirname[PATH_MAX];
	size_t dirlen = sizeof(dirname);
	struct expected_dir *cur_dir;
	struct expected_dir expected_dirs[] = {
		{
			.dirname = "dir_1",
			.checked = 0
		},
		{
			.dirname = "dir_2",
			.checked = 0
		},
		{ NULL, 0 }
	};

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init(\"%s\") returned %d\n", dir, retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	/* Create directory tree */
	create_dir_tree(fs);

	retval = fsroot_opendir(fs, "dir", &dh, &err);
	ck_assert_msg(retval == S_OK, "fsroot_opendir(\"dir\") returned %d\n", retval);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_OK, "fsroot_readdir() returned %d (1st time)\n", retval);
	ck_assert_msg(check_dir(dirname, expected_dirs),
		"Directory '%s' returned but not found\n", dirname);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_OK, "fsroot_readdir() returned %d (2nd time)\n", retval);
	ck_assert_msg(check_dir(dirname, expected_dirs),
		"Directory '%s' returned but not found\n", dirname);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (1st time)\n", retval);
	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (2nd time)\n", retval);

	/* Check that all the expected directories have been checked */
	for (cur_dir = expected_dirs; cur_dir->dirname; cur_dir++) {
		ck_assert_msg(cur_dir->checked,
			"Directory '%s' has not been checked\n", cur_dir->dirname);
	}

	fsroot_closedir(&dh);
	ck_assert(fsroot_readdir(dh, dirname, dirlen, &err) == E_BADARGS);

	fsroot_deinit(&fs);
}
END_TEST

START_TEST(test_fsroot_readdir_too_short_buf)
{
	fsroot_t *fs;
	void *dh;
	int retval, err;
	char dirname[PATH_MAX];
	size_t dirlen = sizeof(dirname);
	struct expected_dir *cur_dir;
	struct expected_dir expected_dirs[] = {
		{
			.dirname = "dir_1",
			.checked = 0
		},
		{
			.dirname = "dir_2",
			.checked = 0
		},
		{ NULL, 0 }
	};

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init(\"%s\") returned %d\n", dir, retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	/* Create directory tree */
	create_dir_tree(fs);

	retval = fsroot_opendir(fs, "dir", &dh, &err);
	ck_assert_msg(retval == S_OK, "fsroot_opendir(\"dir\") returned %d\n", retval);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_OK, "fsroot_readdir() returned %d (1st time)\n", retval);
	ck_assert_msg(check_dir(dirname, expected_dirs),
		"Directory '%s' returned but not found\n", dirname);

	retval = fsroot_readdir(dh, dirname, 1, &err);
	ck_assert_msg(retval == E_NOMEM, "fsroot_readdir() returned %d "
			"(should return FSROOT_E_NOMEM) (1st time)\n", retval);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_OK, "fsroot_readdir() returned %d (2nd time)\n", retval);
	ck_assert_msg(check_dir(dirname, expected_dirs),
		"Directory '%s' returned but not found\n", dirname);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (1st time)\n", retval);
	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (2nd time)\n", retval);
	retval = fsroot_readdir(dh, dirname, 2, &err);
	ck_assert_msg(retval == S_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (3rd time)\n", retval);

	/* Check that all the expected directories have been checked */
	for (cur_dir = expected_dirs; cur_dir->dirname; cur_dir++) {
		ck_assert_msg(cur_dir->checked,
			"Directory '%s' has not been checked\n", cur_dir->dirname);
	}

	fsroot_closedir(&dh);
	ck_assert(fsroot_readdir(dh, dirname, dirlen, &err) == E_BADARGS);

	fsroot_deinit(&fs);
}
END_TEST

START_TEST(test_fsroot_readdir_empty)
{
	fsroot_t *fs;
	void *dh;
	int retval, err;
	char dirname[PATH_MAX];
	size_t dirlen = sizeof(dirname);

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init(\"%s\") returned %d\n", dir, retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	/* This time we only create one single empty directory */
	ck_assert_int_eq(fsroot_mkdir(fs, "dir", 1000, 1000, 0040700), S_OK);

	retval = fsroot_opendir(fs, "dir", &dh, &err);
	ck_assert_msg(retval == S_OK, "fsroot_opendir(\"dir\") returned %d\n", retval);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (1st time)\n", retval);
	retval = fsroot_readdir(dh, dirname, 3, &err);
	ck_assert_msg(retval == S_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (2nd time)\n", retval);

	fsroot_closedir(&dh);
	ck_assert(fsroot_readdir(dh, dirname, dirlen, &err) == E_BADARGS);

	fsroot_deinit(&fs);
}
END_TEST

START_TEST(test_fsroot_readdir_external_dir)
{
	fsroot_t *fs;
	void *dh;
	int retval, err;
	char dirname[PATH_MAX];
	size_t dirlen = sizeof(dirname);

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init(\"%s\") returned %d\n", dir, retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	ck_assert_int_eq(fsroot_mkdir(fs, "dir", 1000, 1000, 0040700), S_OK);

	/* We create one "internal" directory, and an external one */
	ck_assert_int_eq(fsroot_mkdir(fs, "dir/dir_1", 1000, 1000, 0040700), S_OK);
	ck_assert(snprintf(dirname, sizeof(dirname), "%s/dir/dir_2", dir) > 0);
	ck_assert_int_eq(mkdir(dirname, 0040600), 0);

	/* Now, fsroot_readdir() should only list the internal directory */
	retval = fsroot_opendir(fs, "dir", &dh, &err);
	ck_assert_msg(retval == S_OK, "fsroot_opendir(\"dir\") returned %d\n", retval);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_OK, "fsroot_readdir() returned %d\n", retval);
	ck_assert_str_eq(dirname, "dir_1");

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == S_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE)\n", retval);

	fsroot_closedir(&dh);
	ck_assert(fsroot_readdir(dh, dirname, dirlen, &err) == E_BADARGS);

	fsroot_deinit(&fs);
}
END_TEST

void _empty_dir(const char *dir)
{
	DIR *d;
	struct dirent *de;
	struct stat st;
	char path[PATH_MAX];

	d = opendir(dir);
	if (!d)
		ck_abort_msg("Could not open directory '%s'\n", dir);

	do {
		de = readdir(d);
		if (de && strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
			ck_assert(snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) > 0);
			ck_assert(stat(path, &st) == 0);

			if (S_ISDIR(st.st_mode)) {
				if (rmdir(path) == -1) {
					_empty_dir(path);
					ck_assert(rmdir(path) == 0);
				}
			} else {
				ck_assert_msg(unlink(path) == 0,
						"Could not unlink file '%s'\n",
						de->d_name);
			}
		}
	} while (de);

	closedir(d);
}

void empty_dir()
{
	_empty_dir(dir);
}

Suite *fsroot_suite()
{
	Suite *s;
	TCase *tc;

	s = suite_create("fsroot tests");

	tc = tcase_create("core");
	tcase_add_test(tc, test_fsroot_readdir);
	tcase_add_test(tc, test_fsroot_readdir_too_short_buf);
	tcase_add_test(tc, test_fsroot_readdir_empty);
	tcase_add_test(tc, test_fsroot_readdir_external_dir);
	tcase_add_checked_fixture(tc, NULL, empty_dir);

	suite_add_tcase(s, tc);
	return s;
}

int main()
{
	int failed;
	Suite *s;
	SRunner *sr;

	if (mkdir(dir, 0744) == -1) {
		fprintf(stderr, "ERROR: Could not create directory '%s'\n", dir);
		return EXIT_FAILURE;
	}

	s = fsroot_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	if (rmdir(dir) == -1) {
		fprintf(stderr, "ERROR: Could not delete directory '%s'\n", dir);
		return EXIT_FAILURE;
	}

	return failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
