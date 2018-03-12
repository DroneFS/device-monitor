#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <check.h>
#include "../linux/fsroot.h"

char dir[] = "fsroot-root";

START_TEST(test_fsroot_root_path_mkdir_failure)
{
	fsroot_t *fs;
	int retval;

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init(\"%s\") returned %d\n",
			dir, retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	retval = fsroot_mkdir(fs, "/", 1000, 1000, 0040700);
	ck_assert_msg(retval == E_EXISTS, "fsroot_mkdir(\"/\") returned %d (should return %d)\n",
			retval, E_EXISTS);

	fsroot_deinit(&fs);
}
END_TEST

START_TEST(test_fsroot_root_path_getattr)
{
	fsroot_t *fs;
	int retval;
	struct stat st;

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init(\"%s\") returned %d\n",
			dir, retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	retval = fsroot_getattr(fs, "/", &st);
	ck_assert_msg(retval == S_OK, "fsroot_getattr(\"/\") returned %d\n", retval);
	ck_assert_int_eq(st.st_uid, 1000);
	ck_assert_int_eq(st.st_gid, 1000);
	ck_assert_int_eq(st.st_mode, 0040754);
	ck_assert(S_ISDIR(st.st_mode));

	fsroot_deinit(&fs);
}
END_TEST

START_TEST(test_fsroot_root_path_rmdir)
{
	fsroot_t *fs;
	int retval;

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init(\"%s\") returned %d\n",
			dir, retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	retval = fsroot_rmdir(fs, "/");
	ck_assert_msg(retval == E_BADARGS, "fsroot_rmdir(\"/\") returned %d (should return %d)\n",
			retval, E_BADARGS);

	fsroot_deinit(&fs);
}
END_TEST

void empty_dir()
{
	DIR *d;
	struct dirent *de = NULL;
	char path[PATH_MAX];

	d = opendir(dir);
	if (!d)
		ck_abort_msg("Could not open directory '%s'\n", dir);

	do {
		de = readdir(d);
		if (de && strcmp(de->d_name, ".") && strcmp(de->d_name, "..")) {
			ck_assert(snprintf(path, sizeof(path), "%s/%s", dir, de->d_name) > 0);
			ck_assert_msg(unlink(path) == 0,
					"Could not unlink file '%s'\n",
					de->d_name);
		}
	} while (de);

	closedir(d);
}

Suite *fsroot_suite()
{
	Suite *s;
	TCase *tc;

	s = suite_create("fsroot getattr tests");

	tc = tcase_create("core");
	tcase_add_test(tc, test_fsroot_root_path_mkdir_failure);
	tcase_add_test(tc, test_fsroot_root_path_getattr);
	tcase_add_test(tc, test_fsroot_root_path_rmdir);
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
