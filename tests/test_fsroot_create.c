#include <check.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "../linux/fsroot.h"

char dir[] = "fsroot-root";
char foo_data[] = "Hello, world! This is 'foo'.",
	bar_data[] = "Hi, I'm 'bar'!";

void create_foo_and_bar(fsroot_t *fs, char with_trailing_slash)
{
	char foo_path[PATH_MAX], bar_path[PATH_MAX], foo_fullpath[PATH_MAX], bar_fullpath[PATH_MAX];
	int retval, err, fd_foo, fd_bar;
	struct stat st;

	if (with_trailing_slash) {
		strcpy(foo_path, "/foo");
		strcpy(bar_path, "/bar");
	} else {
		strcpy(foo_path, "foo");
		strcpy(bar_path, "bar");
	}

	fd_foo = fsroot_create(fs, foo_path, 1000, 1000, 0100700, O_CREAT | O_RDWR, &err);
	ck_assert_msg(fd_foo >= 0, "fsroot_create(\"foo\") returned %d (err: %d)\n", fd_foo, err);
	fd_bar = fsroot_create(fs, bar_path, 1000, 1000, 0100700, O_RDWR, &err);
	ck_assert_msg(fd_bar >= 0 && fd_bar != fd_foo, "fsroot_create(\"bar\") returned %d (err: %d)\n",
			fd_bar, err);

	/* Generate full paths */
	ck_assert(snprintf(foo_fullpath, sizeof(foo_fullpath), "%s/foo", dir) > 0);
	ck_assert(snprintf(bar_fullpath, sizeof(bar_fullpath), "%s/bar", dir) > 0);

	/* Check that 'foo' was created correctly */
	ck_assert_msg(stat(foo_fullpath, &st) == 0, "stat(\"%s\") failed\n", foo_fullpath);
	ck_assert_msg(S_ISREG(st.st_mode), "File '%s' should be a regular file\n", foo_fullpath);
	ck_assert_msg(st.st_mode == 0100600, "Mode of file '%s' should be 0100600 (was: %#o)\n",
			foo_fullpath, st.st_mode);
	ck_assert_int_eq(st.st_uid, 1000);
	ck_assert_int_eq(st.st_gid, 1000);
	/* Check that 'bar' was created correctly */
	ck_assert_msg(stat(bar_fullpath, &st) == 0, "stat(\"%s\") failed\n", bar_fullpath);
	ck_assert_msg(S_ISREG(st.st_mode), "File '%s' should be a regular file\n", bar_fullpath);
	ck_assert_msg(st.st_mode == 0100600, "Mode of file '%s' should be 0100600 (was: %#o)\n",
			bar_fullpath, st.st_mode);
	ck_assert_int_eq(st.st_uid, 1000);
	ck_assert_int_eq(st.st_gid, 1000);

	retval = fsroot_write(fs, fd_foo, foo_data, sizeof(foo_data) - 1, 0, &err);
	ck_assert_msg(retval == (sizeof(foo_data) - 1), "fsroot_write(\"foo\") returned %d (err: %d)\n",
			retval, err);
	retval = fsroot_write(fs, fd_bar, bar_data, sizeof(bar_data) - 1, 0, &err);
	ck_assert_msg(retval == (sizeof(bar_data) - 1), "fsroot_write(\"bar\") returned %d (err: %d)\n",
			retval, err);
}

void release_foo_and_bar(fsroot_t *fs, char with_trailing_slash)
{
	int retval;
	struct stat st;
	char foo_path[PATH_MAX], bar_path[PATH_MAX], foo_fullpath[PATH_MAX], bar_fullpath[PATH_MAX];

	if (with_trailing_slash) {
		strcpy(foo_path, "/foo");
		strcpy(bar_path, "/bar");
	} else {
		strcpy(foo_path, "foo");
		strcpy(bar_path, "bar");
	}

	/* Generate full paths */
	ck_assert(snprintf(foo_fullpath, sizeof(foo_fullpath), "%s/foo", dir) > 0);
	ck_assert(snprintf(bar_fullpath, sizeof(bar_fullpath), "%s/bar", dir) > 0);

	retval = fsroot_release(fs, foo_path);
	ck_assert_msg(retval == S_OK, "fsroot_release(\"foo\") returned %d\n", retval);
	retval = fsroot_release(fs, bar_path);
	ck_assert_msg(retval == S_OK, "fsroot_release(\"bar\") returned %d\n", retval);

	ck_assert_msg(stat(foo_fullpath, &st) == 0, "stat(\"%s\") failed\n", foo_fullpath);
	ck_assert_msg(S_ISREG(st.st_mode), "File '%s' should be a regular file\n", foo_fullpath);
	ck_assert_msg(stat(bar_fullpath, &st) == 0, "stat(\"%s\") failed\n", bar_fullpath);
	ck_assert_msg(S_ISREG(st.st_mode), "File '%s' should be a regular file\n", bar_fullpath);
}

START_TEST(test_fsroot_create)
{
	fsroot_t *fs;
	int retval;

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init() returned %d\n", retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	create_foo_and_bar(fs, 0);
	release_foo_and_bar(fs, 0);

	fsroot_deinit(&fs);
}
END_TEST

START_TEST(test_fsroot_create_with_trailing_slash)
{
	fsroot_t *fs;
	int retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init() returned %d\n", retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	create_foo_and_bar(fs, 1);
	release_foo_and_bar(fs, 1);

	fsroot_deinit(&fs);
}
END_TEST

START_TEST(test_fsroot_open)
{
	fsroot_t *fs;
	int retval, err = 0;
	int fd_foo, fd_bar;
	char buf[500];
	size_t bufsize = sizeof(buf);

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init() returned %d\n", retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	create_foo_and_bar(fs, 0);
	release_foo_and_bar(fs, 0);

	fd_foo = fsroot_open(fs, "foo", O_CREAT | O_RDONLY);
	ck_assert_msg(fd_foo >= 0, "fsroot_open(\"foo\") returned %d\n",
			fd_foo);
	fd_bar = fsroot_open(fs, "bar", 0);
	ck_assert_msg(fd_bar >= 0 && fd_bar != fd_foo, "fsroot_open(\"bar\") returned %d\n",
			fd_bar);

	memset(buf, 0, bufsize);
	retval = fsroot_read(fs, fd_foo, buf, bufsize, 0, &err);
	ck_assert_msg(retval == strlen(foo_data), "fsroot_read(\"foo\") returned %d (err: %d)\n",
			retval, err);
	ck_assert_str_eq(buf, foo_data);
	memset(buf, 0, bufsize);
	retval = fsroot_read(fs, fd_bar, buf, bufsize, 0, &err);
	ck_assert_msg(retval == strlen(bar_data), "fsroot_read(\"bar\") returned %d (err: %d)\n",
			retval, err);
	ck_assert_str_eq(buf, bar_data);

	retval = fsroot_release(fs, "foo");
	ck_assert_msg(retval == S_OK, "fsroot_release(\"foo\") returned %d\n", retval);
	retval = fsroot_release(fs, "bar");
	ck_assert_msg(retval == S_OK, "fsroot_release(\"bar\") returned %d\n", retval);

	fsroot_deinit(&fs);
}
END_TEST

START_TEST(test_fsroot_open_with_trailing_slash)
{
	fsroot_t *fs;
	int retval, err = 0;
	int fd_foo, fd_bar;
	char buf[500];
	size_t bufsize = sizeof(buf);

	retval = fsroot_init(&fs, NULL);
	ck_assert_msg(retval == S_OK, "fsroot_init() returned %d\n", retval);

	fsroot_set_root_directory(fs, dir);
	retval = fsroot_start(fs, 1000, 1000, 0040754);
	ck_assert_msg(retval == S_OK, "fsroot_start() returned %d\n", retval);

	create_foo_and_bar(fs, 1);
	release_foo_and_bar(fs, 1);

	fd_foo = fsroot_open(fs, "/foo", O_CREAT | O_RDONLY);
	ck_assert_msg(fd_foo >= 0, "fsroot_open(\"/foo\") returned %d\n",
			fd_foo);
	fd_bar = fsroot_open(fs, "/bar", 0);
	ck_assert_msg(fd_bar >= 0 && fd_bar != fd_foo, "fsroot_open(\"/bar\") returned %d\n",
			fd_bar);

	memset(buf, 0, bufsize);
	retval = fsroot_read(fs, fd_foo, buf, bufsize, 0, &err);
	ck_assert_msg(retval == strlen(foo_data), "fsroot_read(\"/foo\") returned %d (err: %d)\n",
			retval, err);
	ck_assert_str_eq(buf, foo_data);
	memset(buf, 0, bufsize);
	retval = fsroot_read(fs, fd_bar, buf, bufsize, 0, &err);
	ck_assert_msg(retval == strlen(bar_data), "fsroot_read(\"/bar\") returned %d (err: %d)\n",
			retval, err);
	ck_assert_str_eq(buf, bar_data);

	retval = fsroot_release(fs, "/foo");
	ck_assert_msg(retval == S_OK, "fsroot_release(\"/foo\") returned %d\n", retval);
	retval = fsroot_release(fs, "/bar");
	ck_assert_msg(retval == S_OK, "fsroot_release(\"/bar\") returned %d\n", retval);

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

	s = suite_create("fsroot tests");

	tc = tcase_create("core");
	tcase_add_test(tc, test_fsroot_create);
	tcase_add_test(tc, test_fsroot_open);
	tcase_add_test(tc, test_fsroot_create_with_trailing_slash);
	tcase_add_test(tc, test_fsroot_open_with_trailing_slash);
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
