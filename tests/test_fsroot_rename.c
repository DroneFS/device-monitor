#include <check.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include "../linux/fsroot.h"

char dir[] = "fsroot-root";

START_TEST(test_fsroot_rename)
{
	fsroot_t *fs;
	int retval, error = 0;
	struct stat st;

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init(\"%s\") returned %d\n",
			dir, retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	retval = fsroot_create(fs, "foo", 1000, 1000, 0100700, 0, &error);
	ck_assert_msg(retval >= 0 && error == 0, "fsroot_create(\"foo\") returned %d (error: %d)\n",
			retval, error);
	fsroot_release(fs, "foo");

	retval = fsroot_getattr(fs, "foo", &st);
	ck_assert_msg(retval == S_OK, "fsroot_getattr(\"foo\") returned %d\n", retval);
	ck_assert_int_eq(st.st_uid, 1000);
	ck_assert_int_eq(st.st_gid, 1000);
	ck_assert_int_eq(st.st_mode, 0100700);
	ck_assert(S_ISREG(st.st_mode));

	retval = fsroot_rename(fs, "foo", "bar");
	ck_assert_msg(retval == S_OK, "fsroot_rename(\"foo\", \"bar\") returned %d\n", retval);

	ck_assert(fsroot_getattr(fs, "foo", &st) == E_NOTEXISTS);
	retval = fsroot_getattr(fs, "bar", &st);
	ck_assert_msg(retval == S_OK, "fsroot_getattr(\"bar\") returned %d\n", retval);
	ck_assert_int_eq(st.st_uid, 1000);
	ck_assert_int_eq(st.st_gid, 1000);
	ck_assert_int_eq(st.st_mode, 0100700);
	ck_assert(S_ISREG(st.st_mode));

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

	s = suite_create("fsroot symlink tests");

	tc = tcase_create("core");
	tcase_add_test(tc, test_fsroot_rename);
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
