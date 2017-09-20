#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include "../fsroot.h"

char dir[] = "fsroot-root";

void create_dir_tree()
{
	mode_t dirmode = 0040700;
	ck_assert_int_eq(fsroot_mkdir("dir", 1000, 1000, dirmode), FSROOT_OK);
	ck_assert_int_eq(fsroot_mkdir("dir/dir_1", 1000, 1000, dirmode), FSROOT_OK);
	ck_assert_int_eq(fsroot_mkdir("dir/dir_2", 1000, 1000, dirmode), FSROOT_OK);
}

START_TEST(test_fsroot_readdir)
{
	void *dh;
	int retval, err;
	char dirname[PATH_MAX];
	size_t dirlen = sizeof(dirname);

	retval = fsroot_init(dir, 1000, 1000, 0040700);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_init(\"%s\") returned %d\n", dir, retval);

	/* Create directory tree */
	create_dir_tree();

	retval = fsroot_opendir("dir", &dh, &err);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_opendir(\"dir\") returned %d\n", retval);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_readdir() returned %d (1st time)\n", retval);
	ck_assert_str_eq(dirname, "dir_1");

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_readdir() returned %d (2nd time)\n", retval);
	ck_assert_str_eq(dirname, "dir_2");

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (1st time)\n", retval);
	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (2nd time)\n", retval);

	fsroot_closedir(&dh);
	ck_assert(fsroot_readdir(dh, dirname, dirlen, &err) == FSROOT_E_BADARGS);

	fsroot_deinit();
}
END_TEST

START_TEST(test_fsroot_readdir_too_short_buf)
{
	void *dh;
	int retval, err;
	char dirname[PATH_MAX];
	size_t dirlen = sizeof(dirname);

	retval = fsroot_init(dir, 1000, 1000, 0040700);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_init(\"%s\") returned %d\n", dir, retval);

	/* Create directory tree */
	create_dir_tree();

	retval = fsroot_opendir("dir", &dh, &err);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_opendir(\"dir\") returned %d\n", retval);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_readdir() returned %d (1st time)\n", retval);
	ck_assert_str_eq(dirname, "dir_1");

	retval = fsroot_readdir(dh, dirname, 1, &err);
	ck_assert_msg(retval == FSROOT_E_NOMEM, "fsroot_readdir() returned %d "
			"(should return FSROOT_E_NOMEM) (1st time)\n", retval);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_readdir() returned %d (2nd time)\n", retval);
	ck_assert_str_eq(dirname, "dir_2");

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (1st time)\n", retval);
	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (2nd time)\n", retval);
	retval = fsroot_readdir(dh, dirname, 2, &err);
	ck_assert_msg(retval == FSROOT_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (3rd time)\n", retval);

	fsroot_closedir(&dh);
	ck_assert(fsroot_readdir(dh, dirname, dirlen, &err) == FSROOT_E_BADARGS);

	fsroot_deinit();
}
END_TEST

START_TEST(test_fsroot_readdir_empty)
{
	void *dh;
	int retval, err;
	char dirname[PATH_MAX];
	size_t dirlen = sizeof(dirname);

	retval = fsroot_init(dir, 1000, 1000, 0040700);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_init(\"%s\") returned %d\n", dir, retval);

	/* This time we only create one single empty directory */
	ck_assert_int_eq(fsroot_mkdir("dir", 1000, 1000, 0040700), FSROOT_OK);

	retval = fsroot_opendir("dir", &dh, &err);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_opendir(\"dir\") returned %d\n", retval);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (1st time)\n", retval);
	retval = fsroot_readdir(dh, dirname, 3, &err);
	ck_assert_msg(retval == FSROOT_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE) (2nd time)\n", retval);

	fsroot_closedir(&dh);
	ck_assert(fsroot_readdir(dh, dirname, dirlen, &err) == FSROOT_E_BADARGS);

	fsroot_deinit();
}
END_TEST

START_TEST(test_fsroot_readdir_external_dir)
{
	void *dh;
	int retval, err;
	char dirname[PATH_MAX];
	size_t dirlen = sizeof(dirname);

	retval = fsroot_init(dir, 1000, 1000, 0040700);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_init(\"%s\") returned %d\n", dir, retval);

	ck_assert_int_eq(fsroot_mkdir("dir", 1000, 1000, 0040700), FSROOT_OK);

	/* We create one "internal" directory, and an external one */
	ck_assert_int_eq(fsroot_mkdir("dir/dir_1", 1000, 1000, 0040700), FSROOT_OK);
	ck_assert(snprintf(dirname, sizeof(dirname), "%s/dir/dir_2", dir) > 0);
	ck_assert_int_eq(mkdir(dirname, 0040600), 0);

	/* Now, fsroot_readdir() should only list the internal directory */
	retval = fsroot_opendir("dir", &dh, &err);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_opendir(\"dir\") returned %d\n", retval);

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_OK, "fsroot_readdir() returned %d\n", retval);
	ck_assert_str_eq(dirname, "dir_1");

	retval = fsroot_readdir(dh, dirname, dirlen, &err);
	ck_assert_msg(retval == FSROOT_NOMORE, "fsroot_readdir() returned %d "
			"(should return FSROOT_NOMORE)\n", retval);

	fsroot_closedir(&dh);
	ck_assert(fsroot_readdir(dh, dirname, dirlen, &err) == FSROOT_E_BADARGS);

	fsroot_deinit();
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
